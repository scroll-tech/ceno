# Appendix

## GKR Protocol for Tower Tree

In Ceno, grand product checks (used for offline memory checking, permutation arguments, etc.)
require computing a product of the form $\prod_{i} a_i$. We use a **complete binary tree of
multiplication gates** — called a **tower tree** — and verify its computation via the
[GKR protocol](https://people.cs.georgetown.edu/jthaler/GKRNote.pdf), following the approach of
[Thaler13, Section 5.3.1].

### The Tree Structure

A tower tree of height $d$ takes $n = 2^d$ inputs and produces a 2-tuple output. The tree
has $d$ layers:

- **Layer $d$** (bottom): the $n$ input values $a_0, a_1, \ldots, a_{n-1}$.
- **Layer $i$** ($1 < i < d$): each gate $p$ multiplies its two children at layer $i+1$.
- **Layer 1** (top): two gates outputting $(b_0, b_1)$ where
  $b_0 = \prod_{i=0}^{n/2-1} a_i$ and $b_1 = \prod_{i=n/2}^{n-1} a_i$.

The wiring is natural: gate $p$ at layer $i$ has left child $(p, 0)$ and right child
$(p, 1)$ at layer $i+1$. Equivalently, the children of gate $p$ are gates $2p$ and
$2p+1$. Every gate computes:

$$
V_i(p) = \tilde{V}_{i+1}(p, 0) \cdot \tilde{V}_{i+1}(p, 1)
$$

The following diagram shows a height-3 tower tree with 8 inputs, outputting
$(b_0, b_1) = (a_0 \cdots a_3,\; a_4 \cdots a_7)$:

<p align="center">
  <img src="images/tower-tree.svg" alt="Tower tree with height 3" width="720" />
</p>

### Applying the GKR Protocol

The GKR protocol verifies the computation layer by layer, from the top down to the inputs.
At each layer, the verifier holds a claim about the multilinear extension $\tilde{V}_i(w)$
for some random point $w$, and reduces it to a claim about $\tilde{V}_{i+1}(\omega)$ via
a sumcheck invocation.

**Claim reduction at each layer.** Suppose the verifier holds a claim
$\tilde{V}_i(w) = c$ for some random point $w$. Since every gate at layer $i$
multiplies its two children at layer $i+1$, the multilinear extension satisfies:

$$
\tilde{V}_i(w) = \sum_{b \in \{0,1\}^{s_i}} \textrm{eq}(w, b) \cdot \tilde{V}_{i+1}(b, 0) \cdot \tilde{V}_{i+1}(b, 1)
$$

where $\tilde{V}_i$ and $\tilde{V}_{i+1}$ are the multilinear extensions of the gate values
at layers $i$ and $i+1$ respectively, and
$\textrm{eq}(w, b) = \prod_{k=1}^{s_i}(w_k b_k + (1 - w_k)(1 - b_k))$ is the multilinear
extension of the equality function (equals 1 when $b = w$ on Boolean inputs).

The verifier reduces this claim by running the **sumcheck protocol** on the right-hand side. The
summand $\textrm{eq}(w, b) \cdot \tilde{V}_{i+1}(b, 0) \cdot \tilde{V}_{i+1}(b, 1)$
has **degree 3** in each variable of $b$ (one degree from $\textrm{eq}$, one from each
$\tilde{V}_{i+1}$ factor). Therefore, each round of the sumcheck protocol requires the prover
to send **4 field elements**.

**Full protocol flow (height-3 example):**

1. **Start:** The verifier has the claimed output $(b_0, b_1)$ and constructs a claim
   $\tilde{V}_1(w) = c$ at a random point $w$.
2. **Layer 1 sumcheck:** Run sumcheck on
   $\sum_{b} \textrm{eq}(w, b) \cdot \tilde{V}_2(b, 0) \cdot \tilde{V}_2(b, 1)$.
   This reduces the claim to evaluations of $\tilde{V}_2$, which the verifier combines into a
   single claim $\tilde{V}_2(w') = c'$ at a new random point $w'$.
3. **Layer 2 sumcheck:** Run sumcheck on
   $\sum_{b} \textrm{eq}(w', b) \cdot \tilde{V}_3(b, 0) \cdot \tilde{V}_3(b, 1)$.
   This reduces to a claim about $\tilde{V}_3$, i.e., an evaluation of the input multilinear
   polynomial $a(x)$ (with 3 variables) at a point $z$. The validity of $(b_0, b_1)$
   is thus reduced to verifying a single evaluation/opening $a(z) = v$.

### Why Tower Trees are Efficient

The regular wiring pattern of the binary tree is what makes Thaler's optimization possible.
Because the children of gate $p$ are simply $(p, 0)$ and $(p, 1)$, the polynomial
$g_z^{(i)}$ has a very simple structure — no complex wiring predicates are needed. This
enables the prover to evaluate $g_z^{(i)}$ at all required points in $O(2^{s_i})$ time
per layer, giving an overall prover runtime of $O(n)$ — **optimal**, matching the cost of
simply evaluating the circuit with no proof at all (up to a constant factor).

In Ceno, tower trees are the backbone of **offline memory checking**: every memory
read/write is verified by computing a grand product via a tower tree, and the GKR protocol
proves this computation correct with a linear-time prover and a logarithmic-time verifier.

### References

- Justin Thaler. *Time-Optimal Interactive Proofs for Circuit Evaluation*. 2013.
  Section 5.3.1: "The Polynomial for a Binary Tree".
  Available at: <https://eprint.iacr.org/2013/351.pdf>
