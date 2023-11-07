import matplotlib.pyplot as plt

x_axis = [1<<exponent for exponent in range(13)]

prover = [1.2, 1.62, 1.75, 1.91, 2.09, 3.37, 2.76, 3.47, 4.71, 6.87, 10.81, 19.45, 33.63]
verifier = [2.92, 4.49, 4.59, 4.75, 4.95, 5.44, 6.09, 6.84, 8.41, 11.32, 13.61, 22.49, 36.49]
encrypt = [3.41, 6.65, 7.99, 5.68, 10.82, 16.54, 32.84, 60.96, 122.42, 231.41, 481.57, 958.53, 1917.4]
enc_check = [1.13, 2.11, 2.37, 1.9, 3.54, 5.78, 11.01, 20.6, 41.22, 80.78, 161.07, 320.77, 643.33]

fig, ax = plt.subplots(num = 1, figsize = (12,9), nrows = 2, ncols = 1, sharex = "col")

ax[0].plot(x_axis, prover, "r--", linewidth = 2.0)
ax[0].plot(x_axis, verifier, "b:", linewidth = 2.0)
ax[0].legend(["prover", "verifier"], loc = "upper left")
ax[0].set_ylabel("time [ms]")
ax[0].set_xscale('log', base = 2)
ax[0].grid(True)

ax[1].plot(x_axis, encrypt, "k--", linewidth = 2.0)
ax[1].plot(x_axis, enc_check, "g:", linewidth = 2.0)
ax[1].legend(["split encryption", "split encryption check"], loc = "upper left")
ax[1].set_ylabel("time [ms]")
ax[1].set_xlabel("data size [BLS12-381 field element]")
ax[1].set_xscale('log', base = 2)
ax[1].grid(True)

plt.tight_layout()
plt.show()
