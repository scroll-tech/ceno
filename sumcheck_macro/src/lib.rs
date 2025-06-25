extern crate proc_macro;
use itertools::Itertools;
use proc_macro2::{Span, TokenStream};
use quote::quote;
use syn::{
    Expr, ExprClosure, Ident, LitBool, LitInt, Result, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

struct SumcheckCodegenMacroInput {
    /// Degree is required to be a literal integer for compile-time codegen
    degree: LitInt,
    /// Whether to parallalize the sumcheck
    parallalize: LitBool,
    /// Closure that gives access to the mle product
    product_access: ExprClosure,
    /// get poly type
    get_poly_meta: ExprClosure,
}

impl Parse for SumcheckCodegenMacroInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let degree = input.parse()?;
        input.parse::<Token![,]>()?;

        let parallalize: LitBool = input.parse()?; // `<bool>`
        input.parse::<Token![,]>()?; // `,`

        let expr1: Expr = input.parse()?;
        input.parse::<Token![,]>()?; // `,`

        let expr2: Expr = input.parse()?;

        let product_access = match expr1 {
            Expr::Closure(product_access) => product_access,
            _ => Err(syn::Error::new_spanned(
                expr1,
                "Expected closure that gives access to the mle product",
            ))?,
        };

        let get_poly_meta = match expr2 {
            Expr::Closure(get_poly_meta) => get_poly_meta,
            _ => Err(syn::Error::new_spanned(
                expr2,
                "Expected closure that get poly type",
            ))?,
        };

        Ok(Self {
            degree,
            parallalize,
            product_access,
            get_poly_meta,
        })
    }
}

#[allow(unused_macros)]
#[proc_macro]
/// Generate code for sumcheck step2.
pub fn sumcheck_code_gen(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as SumcheckCodegenMacroInput);

    let degree = input.degree.base10_parse::<u32>().unwrap();
    let parallalize = input.parallalize.value;
    let product_access = input.product_access;
    let get_poly_meta = input.get_poly_meta;

    // Part 1 - Declare f vars
    // Code output
    let mut out = quote! {
        // Declaring product access closure in a variable
        let product_access = #product_access;
    };

    // Declare vars to access flattened_ml_extensions from products
    // let f0 = product_access(0u32);
    // let f1 = product_access(1u32);
    // ...
    let mut f_var_names = Vec::new();
    for i in 1..=degree {
        let f_var_name = ident(format!("f{}", i));
        let idx = (i - 1) as usize;
        out = quote! {
            #out
            let #f_var_name = product_access(#idx);
        };
        f_var_names.push(f_var_name);
    }

    // Part 2 - Sort f vars based on FieldType.
    // match (&f0.evaluations(), &f1.evalutations(), ...) {
    //     (FieldType::Base(base1), FieldType::Base(base2), ...) => {...}
    //     ...
    // }
    let match_input = f_var_names.iter().fold(TokenStream::new(), |acc, f| {
        acc_list(acc, quote! {&#f.evaluations()})
    });

    // There are 2^degree possible combinations of Base and Ext evaluations, but
    // since it is commutative, we only need to consider degree+1 combinations, hence
    // we have to forward the rest of the combinations to the default case. The way it
    // is done here is by sorting.
    let mut sorter_match_arms = TokenStream::new();
    for case in 0..(2u32.pow(degree)) {
        // 0 -> Ext
        // 1 -> Base
        let bits_og = (0..degree)
            .enumerate()
            .map(|(idx, shift)| (idx, (case >> shift) & 1))
            .collect::<Vec<_>>();

        let mut bits_sorted = bits_og.clone();
        bits_sorted.sort_by_key(|v| v.1);

        // If we come across a case where idx decreases, means this case was sorted.
        let is_sorted = bits_sorted.iter().tuple_windows().any(|(a, b)| a.0 > b.0);

        // Only print the arm if this case is sorted. Skip if this case was not sorted then it's one of
        // those degree+1 cases and will be added to the next match statement.
        if is_sorted {
            let arm = bits_og.iter().fold(TokenStream::new(), |acc, (_, bit)| {
                // 0 -> Ext
                // 1 -> Base
                let field_type = if *bit == 0u32 {
                    quote! {FieldType::Ext(_)}
                } else {
                    quote! {FieldType::Base(_)}
                };
                acc_list(acc, quote! {#field_type})
            });

            let arm_body = bits_sorted
                .iter()
                .fold(TokenStream::new(), |acc, (idx, _)| {
                    let f = &f_var_names[*idx];
                    acc_list(acc, quote! {#f})
                });

            sorter_match_arms = quote! {
                #sorter_match_arms
                (#arm) => (#arm_body),
            };
        }
    }

    let f_tuple = f_var_names
        .iter()
        .fold(TokenStream::new(), |acc, f| acc_list(acc, quote! {#f}));

    // Generate the first match statement to sort the f vars.
    out = quote! {
        #out

        let (#f_tuple) = match (#match_input) {
            #sorter_match_arms
            _ => (#f_tuple),
        };
    };

    // Part 3 - AdditiveArray
    // Generate c declarations used for optimising additions
    let mut c_declarations = TokenStream::new();
    for i in 1..=degree {
        if degree >= 2 {
            let n = degree - 1;
            let n_bits = n.ilog2() + 1;
            let v = ident(format!("v{i}"));
            for j in 0..n_bits {
                let c = ident(format!("c{i}_{}", j));
                let declaration = if j == 0 {
                    quote! { let #c = #v[b + 1] - #v[b]; }
                } else {
                    let c_last = ident(format!("c{i}_{}", j - 1));
                    quote! { let #c = #c_last + #c_last; }
                };
                c_declarations = quote! {
                    #c_declarations
                    #declaration
                };
            }
        }
    }

    // Generate AdditiveArray based on degree, for usage in match statement.
    let additive_converter = {
        let mut additive_array_items = TokenStream::new();
        let mut additive_array_first_item = TokenStream::new();

        // Generate degree+1 row elements in AdditiveArray
        for i in 1..=(degree + 1) {
            let item = mul_exprs(
                (1..=degree)
                    .map(|j: u32| {
                        let v = ident(format!("v{j}"));
                        // Based on the current row element's degree i, generate the expression.
                        match i {
                            1 => quote! {#v[b]},
                            2 => quote! {#v[b + 1]},
                            _ => {
                                // We could do repeatedly add `#v[b + 1] - #v[b]`, but to optimise the
                                // arithmetic operations, we precompute the values of `#v[b + 1] - #v[b]`
                                // and store them in `c_declarations`. Then we can use these precomputed
                                // c values to generate the expression.
                                //
                                // For example, c0 = #v[b + 1] - #v[b]
                                // i = 3 means 1 x c0
                                // i = 4 means 2 x c0 = c1
                                // i = 5 means 3 x c0 = c0 + c1
                                // i = 6 means 4 x c0 = c2
                                // i = 7 means 5 x c0 = c0 + c2
                                let c_terms = idx_of_one_bits(i - 2).iter().fold(
                                    TokenStream::new(),
                                    |acc, k| {
                                        let c = ident(format!("c{j}_{}", k));
                                        acc_add(acc, c)
                                    },
                                );
                                quote! {#c_terms + #v[b + 1]}
                            }
                        }
                    })
                    .collect(),
            );

            if i == 1 {
                additive_array_first_item = item.clone();
            }
            additive_array_items = acc_list(additive_array_items, item);
        }

        let additive_array_items = quote! {
            #c_declarations
            AdditiveArray([#additive_array_items])
        };

        let iter = if parallalize {
            quote! {.into_par_iter().step_by(2).rev().with_min_len(64)}
        } else {
            quote! {.step_by(2).rev()}
        };

        // Generate the final AdditiveArray expression.

        // special case: generate product for polynomial num_var less than current expected num_var
        // which happened when we batching sumcheck with different num_vars
        let product = mul_exprs(
            (1..=degree)
                .map(|j: u32| {
                    let v = ident(format!("v{j}"));
                    quote! {#v[b]}
                })
                .collect(),
        );

        let degree_plus_one = (degree + 1) as usize;
        quote! {
            // To deal with different num_vars, we exploit a fact that for each product which num_vars < max_num_vars
            // we actually need to have a full sum, times 2^(bh_num_vars - num_vars) to accumulate into univariate computation
            // E.g. Giving multivariate poly f(X) = f_1(X1) + f_2(X), X1 \in {F}^{n'}, X \in {F}^{n}, |X1| := n', |X| = n, n' <= n
            // For i < n - n', to compute univariate poly, f^i(x), b is i-th round boolean hypercube
            // f^i[0] = \sum_b f(r, 0, b), b \in {0, 1}^{n-i-1}, r \in {F}^{n-i-1} challenge get from prev rounds
            //        = \sum_b f_1(b) + f_2(r, 0, b)
            //        = 2^(|b| - |b1|)  * \sum_b1 f_1(b1)  + \sum_b f_2(r, 0, b)
            // b1 is suffix alignment with b
            // same applied on f^i[1], f^i[2], ... f^i[degree + 1]
            // It imply that, for every evals in f_1, to compute univariate poly, we just need to times a factor 2^(|b| - |b1|) for it evaluation value

            // NOTE: current method work in suffix alignment order
            let num_var = ceil_log2(v1.len());
            let expected_numvars_at_round = self.expected_numvars_at_round();
            let get_poly_meta = #get_poly_meta;
            let poly_type = get_poly_meta();

            match poly_type {
                PolyMeta::Phase2Only => {
                    // only main worker doing the calculation of phase2 only polynomial in order to avoid duplicate computation
                    if self.is_main_worker {
                        let mut sum = (0..largest_even_below(v1.len())).map(
                            |b| {
                                #product
                            },
                        ).sum();
                        let num_vars_multiplicity = self.expected_numvars_at_round()
                            // the expected num_vars if working on single thread sumcheck
                            .saturating_add(self.phase2_numvar.unwrap_or(0))
                            // minus one because when expected num of var is n_i, the boolean hypercube dimension only n_i-1
                            .saturating_sub(1)
                            // the multiplicity
                            .saturating_sub(num_var);
                        if num_vars_multiplicity > 0 {
                            sum *= E::BaseField::from_canonical_u64(1 << num_vars_multiplicity);
                        }
                        AdditiveArray::<_, #degree_plus_one>([sum; #degree_plus_one])
                    } else {
                        // other just skip and return 0 array
                        AdditiveArray::<_, #degree_plus_one>([Default::default(); #degree_plus_one])
                    }
                },
                PolyMeta::Normal => {
                    if num_var < expected_numvars_at_round {
                        // TODO optimize by caching computed result for later round reuse
                        // need to figure out how to cache in one place to support base/extension field
                        let mut sum = (0..largest_even_below(v1.len())).map(
                            |b| {
                                #product
                            },
                        ).sum();

                        // calculate multiplicity term
                        // minus one because when expected num of var is n_i, the boolean hypercube dimension only n_i-1
                        let num_vars_multiplicity = self.expected_numvars_at_round()
                            .saturating_sub(1)
                            .saturating_sub(num_var);
                        if num_vars_multiplicity > 0 {
                            sum *= E::BaseField::from_canonical_u64(1 << num_vars_multiplicity);
                        }
                        AdditiveArray::<_, #degree_plus_one>([sum; #degree_plus_one])
                    } else {
                        if v1.len() == 1 {
                            let b = 0;
                            AdditiveArray::<_, #degree_plus_one>([#additive_array_first_item ; #degree_plus_one])
                        } else {
                            (0..largest_even_below(v1.len()))
                                #iter
                                .map(|b| {
                                    #additive_array_items
                                })
                                .sum::<AdditiveArray<_, #degree_plus_one>>()
                        }
                    }
                },
            }
        }
    };

    // Since f vars are sorted already, any Bases will tend to right side and Exts to left side.
    let mut match_arms = TokenStream::new();
    for num_exts in 0..=degree {
        // 0 -> Ext
        // 1 -> Base
        let arg_items = std::iter::repeat_n(0, (degree - num_exts) as usize)
            .chain(std::iter::repeat_n(1, num_exts as usize))
            .enumerate()
            .map(|(i, field_type)| {
                let arg_id = i + 1;
                (arg_id, field_type, ident(format!("v{arg_id}")))
            })
            .collect::<Vec<(usize, usize, Ident)>>();

        // Generate the arguments for this match arm.
        let arm_args = arg_items
            .iter()
            .fold(TokenStream::new(), |acc, (_, field_type, ident)| {
                let arg = match field_type {
                    0 => quote! {FieldType::Ext(#ident)},
                    1 => quote! {FieldType::Base(#ident)},
                    _ => unreachable!(),
                };
                acc_list(acc, arg)
            });

        // Generate the body for this match arm.
        // Convert inner type from E::BaseField to E if it is required.
        let arm_body = if num_exts == degree {
            quote! {
                let result = {#additive_converter};
                AdditiveArray(result.0.map(|b| b.into()))
            }
        } else {
            quote! {
                #additive_converter
            }
        };

        // Generate the match arm for this case.
        match_arms = quote! {
            #match_arms
            (#arm_args) => {#arm_body},
        };
    }

    // Generate the second match statement that maps f vars to AdditiveArray.
    out = quote! {
        {
            #out
            match (#match_input) {
                #match_arms
                _ => unreachable!(),
            }
        }
    };

    out.into()
}

fn ident(s: String) -> Ident {
    Ident::new(&s, Span::call_site())
}

fn acc_add(acc: TokenStream, c: Ident) -> TokenStream {
    if acc.is_empty() {
        quote! {#c}
    } else {
        quote! {#acc + #c}
    }
}

fn acc_list(acc: TokenStream, c: TokenStream) -> TokenStream {
    if acc.is_empty() {
        quote! {#c}
    } else {
        quote! {#acc, #c}
    }
}

fn mul_exprs(exprs: Vec<TokenStream>) -> TokenStream {
    join_exprs(quote! {*}, true, exprs)
}

fn join_exprs(op: TokenStream, parenthesis: bool, exprs: Vec<TokenStream>) -> TokenStream {
    exprs
        .iter()
        .enumerate()
        .fold(TokenStream::new(), |acc, (i, expr)| {
            if acc.is_empty() {
                quote! {#expr}
            } else if i < 2 && !parenthesis {
                quote! { #acc #op #expr }
            } else {
                quote! { (#acc) #op (#expr) }
            }
        })
}

fn idx_of_one_bits(n: u32) -> Vec<u32> {
    let mut res = vec![];
    let n_bits = n.ilog2() + 1;
    for j in 0..n_bits {
        if (n >> j) & 1 == 1 {
            res.push(j);
        }
    }
    res
}
