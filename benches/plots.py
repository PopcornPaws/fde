import matplotlib.pyplot as plt
import numpy as np

x_axis = [1<<exponent for exponent in range(13)]

proof_gen = [179.88, 96.14, 55.80, 36.42, 27.02, 22.34, 20.25, 19.42, 19.86, 20.83, 22.90, 27.60, 33.47]
proof_vfy = [6.01, 7.54, 7.63, 7.78, 8.03, 8.54, 9.16, 10.20, 11.83, 14.12, 17.68, 27.90, 41.65]
enc_check = [1.13, 2.11, 2.37, 1.9, 3.54, 5.78, 11.01, 20.6, 41.22, 80.78, 161.07, 320.77, 643.33]

fig, ax = plt.subplots(num = 1, figsize = (12,9), nrows = 2, ncols = 1, sharex = "col")

ax[0].plot(x_axis, proof_gen, linewidth = 2.0)
#ax[0].plot(x_axis, verifier, "b:", linewidth = 2.0)
#ax[0].legend(["prover", "verifier"], loc = "upper left")
ax[0].set_ylabel("prover time [ms]")
ax[0].set_xscale('log', base = 2)
ax[0].grid(True)

ax[1].plot(x_axis, np.array(proof_vfy) + np.array(enc_check), linewidth = 2.0)
#ax[1].plot(x_axis, encrypt, "k--", linewidth = 2.0)
#ax[1].plot(x_axis, enc_check, "g:", linewidth = 2.0)
#ax[1].legend(["split encryption", "split encryption check"], loc = "upper left")
ax[1].set_ylabel("verifier time [ms]")
ax[1].set_xlabel("data size [BLS12-381 field element]")
ax[1].set_xscale('log', base = 2)
ax[1].grid(True)

plt.tight_layout()
plt.show()
