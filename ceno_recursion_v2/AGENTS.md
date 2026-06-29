# Tower Coding Style

- Prefer semantic names over overloaded names:
  `chip_id` is the VK/proof-map identity; `chip_idx` is the proof-local chip index.

- Avoid duplicate fields when they mean the same thing:
  do not keep both `idx` and `chip_idx` in the same AIR column struct.

- Use explicit first-row flags for nested loops:
  `is_first_proof_idx`, `is_first_chip_idx`, then `layer_idx`.

- Keep paired claim names consistent:
  `*_next` means contribution to `C_{i+1}(rho, mu)`;
  `*_cur` means contribution to current-layer expected eval `T_i(rho)`.

- Prefer grouped comments over repetitive per-field comments:
  one concise comment for a naming pattern is better than repeated comments for each read/write/LogUp field.

- Comments should explain protocol meaning, not restate the field name.
