# Appendix

Ceno's GKR layers invoke several sub-PIOPs, each checking a specific
structural constraint with its own sumcheck. The table below summarises
the sub-PIOPs currently documented, with links to the full notes.

| PIOP | Purpose | Sumcheck instances | Opening points per committed MLE |
|---|---|---|---|
| [GKR for Grand Product](./appendix/tower_tree.md) | Grand product $\prod_i a_i$ of $N = 2^d$ inputs | $d - 1$ | Input MLE $a$ at a single point $z \in B_d$ |
| [Local Rotation PIOP](./appendix/local-rotation-piop.md) | Round-to-round state transition for round-based computations (e.g. Keccak-f) | $1$ | Each $f_j$ at three points $(\mathbf{s}_r, \mathbf{s}_i), (\mathbf{p}_0, \mathbf{s}_i), (\mathbf{p}_1, \mathbf{s}_i) \in B_m \times B_n$ |
| [EC-Sum Quark PIOP](./appendix/ec-sum-quark.md) | Sum $\sum_i P_i$ of EC points on a short-Weierstrass curve | $1$ | $x, y$ at $(\mathbf{r}, 0), (\mathbf{r}, 1), (1, \mathbf{r}) \in B_{n+1}$;  $s$ at $(1, \mathbf{r})$ |
