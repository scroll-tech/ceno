extern crate proc_macro;
use proc_macro2::Span;
use quote::quote;
use syn::{
    Expr, ExprClosure, Ident, LitBool, LitInt, Result, Token,
    parse::{Parse, ParseStream},
    parse_macro_input,
};

struct MyMacroInput {
    degree: LitInt,
    parallalize: LitBool,
    product_access: ExprClosure,
}

impl Parse for MyMacroInput {
    fn parse(input: ParseStream) -> Result<Self> {
        let degree = input.parse()?;
        input.parse::<Token![,]>()?;

        let parallalize: LitBool = input.parse()?; // `<bool>`
        input.parse::<Token![,]>()?; // `,`

        let expr = input.parse()?;
        match expr {
            Expr::Closure(product_access) => Ok(Self {
                degree,
                parallalize,
                product_access,
            }),
            _ => Err(syn::Error::new_spanned(
                expr,
                "Expected closure that gives access to the mle product",
            )),
        }
    }
}

#[allow(unused_macros)]
#[proc_macro]
pub fn sumcheck_code_gen(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as MyMacroInput);

    let degree = input.degree.base10_parse::<u32>().unwrap();
    let parallalize = input.parallalize.value;
    let product_access = input.product_access;

    // Output: let product_access = |i| closure_raw_code;
    let mut out = quote! {
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

    // Generate c declarations for optimising additions
    let mut c_declarations = proc_macro2::TokenStream::new();
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

    // Generate AdditiveArray based on degree to be used in match.
    let additive_converter = {
        // Generate AdditiveArray based on degree
        let mut additive_array_items = proc_macro2::TokenStream::new();
        for i in 1..=(degree + 1) {
            let item = join_expr(
                quote! {*},
                true,
                (1..=degree)
                    .map(|j: u32| {
                        let v = ident(format!("v{j}"));
                        match i {
                            1 => quote! {#v[b]},
                            2 => quote! {#v[b + 1]},
                            _ => {
                                let c = idx_of_one_bits(i - 2).iter().fold(
                                    proc_macro2::TokenStream::new(),
                                    |acc, k| {
                                        let c = ident(format!("c{j}_{}", k));
                                        if acc.is_empty() {
                                            quote! {#c}
                                        } else {
                                            quote! {#acc + #c}
                                        }
                                    },
                                );
                                quote! {#c + #v[b + 1]}
                            }
                        }
                    })
                    .collect(),
            );

            if i == 1 {
                additive_array_items = quote! {#item};
            } else {
                additive_array_items = quote! {#additive_array_items, #item};
            }
        }
        let additive_array_items = quote! {
            #c_declarations
            AdditiveArray([#additive_array_items])
        };
        let additive_array_first_item =
            (1..=degree).fold(proc_macro2::TokenStream::new(), |acc, i| {
                let name = ident(format!("v{i}"));
                if acc.is_empty() {
                    quote! {#name[0]}
                } else {
                    quote! {#acc * #name[0]}
                }
            });

        let degree_plus_one = (degree + 1) as usize;
        let iter = if parallalize {
            quote! {.into_par_iter().step_by(2).with_min_len(64)}
        } else {
            quote! {.step_by(2).rev()}
        };
        quote! {
                let res = (0..largest_even_below(v1.len()))
                    #iter
                    .map(|b| {
                        #additive_array_items
                    })
                    .sum::<AdditiveArray<_, #degree_plus_one>>();
                let res = if v1.len() == 1 {
                    AdditiveArray::<_, #degree_plus_one>([#additive_array_first_item ; #degree_plus_one])
                } else {
                    res
                };
                let num_vars_multiplicity = self.poly.aux_info.max_num_variables - (ceil_log2(v1.len()).max(1) + self.round - 1);
                if num_vars_multiplicity > 0 {
                    AdditiveArray(res.0.map(|e| e * E::BaseField::from(1 << num_vars_multiplicity)))
                } else {
                    res
                }

        }
    };

    // Map flattened_ml_extensions evaluations
    // match (&f0.evaluations(), &f1.evalutations(), ...) {
    //     (FieldType::Base(base1), FieldType::Base(base2), ...) => {...}
    //     ...
    // }
    let match_input = f_var_names
        .iter()
        .fold(proc_macro2::TokenStream::new(), |acc, f| {
            if acc.is_empty() {
                quote! {&#f.evaluations()}
            } else {
                quote! {#acc, &#f.evaluations()}
            }
        });

    // There are 2^degree possible combinations of Base and Ext evaluations, but
    // since it is commutative, we only need to consider degree+1 combinations, hence
    // we have to forward the rest of the combinations to the default case. The way it
    // is done here is by sorting.
    let mut sorter_match_arms = proc_macro2::TokenStream::new();
    for case in 0..(2u32.pow(degree)) {
        // 1 -> Ext
        // 0 -> Base
        let bits_og = (0..degree)
            .enumerate()
            .map(|(idx, shift)| (idx, (case >> shift) & 1))
            .collect::<Vec<_>>();

        let mut bits_sorted = bits_og.clone();
        bits_sorted.sort_by(|a, b| a.1.cmp(&b.1));

        let is_sorted = bits_sorted
            .iter()
            .fold((false, 0), |(is_sorted, last_idx), (idx, _)| {
                if last_idx > *idx {
                    (true, *idx)
                } else {
                    (is_sorted, *idx)
                }
            });

        if is_sorted.0 {
            let arm = bits_og
                .iter()
                .fold(proc_macro2::TokenStream::new(), |acc, (_, bit)| {
                    // 1 -> Ext
                    // 0 -> Base
                    let field_type = if *bit == 0u32 {
                        quote! {FieldType::Ext(_)}
                    } else {
                        quote! {FieldType::Base(_)}
                    };
                    if acc.is_empty() {
                        quote! {#field_type}
                    } else {
                        quote! {#acc, #field_type}
                    }
                });

            let arm_body =
                bits_sorted
                    .iter()
                    .fold(proc_macro2::TokenStream::new(), |acc, (idx, _)| {
                        let f = &f_var_names[*idx];
                        if acc.is_empty() {
                            quote! {#f}
                        } else {
                            quote! {#acc, #f}
                        }
                    });

            sorter_match_arms = quote! {
                #sorter_match_arms
                (#arm) => (#arm_body),
            };
        }
    }

    let f_tuple = f_var_names
        .iter()
        .fold(proc_macro2::TokenStream::new(), |acc, f| {
            if acc.is_empty() {
                quote! {#f}
            } else {
                quote! {#acc, #f}
            }
        });

    out = quote! {
        #out

        let (#f_tuple) = match (#match_input) {
            #sorter_match_arms
            _ => (#f_tuple),
        };
    };

    // Now we have sorted the f. If any Bases will tend to left side and Exts to right side.
    let mut match_arms = proc_macro2::TokenStream::new();
    for num_exts in 0..=degree {
        // 1 -> Ext
        // 0 -> Base
        let items = std::iter::repeat_n(0, (degree - num_exts) as usize)
            .chain(std::iter::repeat_n(1, num_exts as usize))
            .enumerate()
            .map(|(i, field_type)| {
                let name = match field_type {
                    0 => format!("v{}", i + 1),
                    1 => format!("v{}", i + 1),
                    _ => unreachable!(),
                };
                (i + 1, field_type, ident(name))
            })
            .collect::<Vec<(usize, usize, Ident)>>();

        let arm_args = items.iter().fold(
            proc_macro2::TokenStream::new(),
            |acc, (_, field_type, ident)| {
                let arg = match field_type {
                    0 => quote! {FieldType::Ext(#ident)},
                    1 => quote! {FieldType::Base(#ident)},
                    _ => unreachable!(),
                };
                if acc.is_empty() {
                    quote! {#arg}
                } else {
                    quote! {#acc, #arg}
                }
            },
        );

        let mut arm_body =
            items
                .iter()
                .fold(proc_macro2::TokenStream::new(), |acc, (i, _, ident)| {
                    let f = &f_var_names[*i - 1];
                    quote! {
                        #acc
                        let #ident = if let Some((start, offset)) = #f.evaluations_range() {
                            &#ident[start..][..offset]
                        } else {
                            &#ident[..]
                        };
                    }
                });
        arm_body = if num_exts == degree {
            quote! {
                #arm_body
                let result = {#additive_converter};
                AdditiveArray(result.0.map(E::from))
            }
        } else {
            quote! {
                #arm_body
                #additive_converter
            }
        };

        match_arms = quote! {
            #match_arms
            (#arm_args) => {#arm_body},
        };
    }
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

fn join_expr(
    op: proc_macro2::TokenStream,
    parenthesis: bool,
    exprs: Vec<proc_macro2::TokenStream>,
) -> proc_macro2::TokenStream {
    exprs
        .iter()
        .enumerate()
        .fold(proc_macro2::TokenStream::new(), |acc, (i, expr)| {
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