import matplotlib.pyplot as plt
import numpy as np
import matplotlib.ticker as ticker

def sizeof_fmt(x, pos):
    if x<0:
        return ""
    for x_unit in ['bytes', 'kB', 'MB', 'GB', 'TB']:
        if x < 1024.0:
            return "%3.1f %s" % (x, x_unit) if x_unit != 'bytes' else "%3.0f %s" % (x, x_unit)
        x /= 1024.0

def time_fmt(x, pos):
    if x<0:
        return ""
    x_unit = ['ms', 's', 'min']
    if x < 1000:
        return "%3.1f %s" % (x, x_unit[0])
    x /= 1000
    if x < 60:
        return "%3.1f %s" % (x, x_unit[1])
    x /= 60
    return "%3.2f %s" % (x, x_unit[2])

def time_lossy_fmt(x, pos):
    if x<0:
        return ""
    x_unit = ['ms', 's', 'min']
    if x < 1000:
        return "%3.0f %s" % (x, x_unit[0])
    x /= 1000
    if x < 60:
        return "%3.1f %s" % (x, x_unit[1])
    x /= 60
    return "%3.2f %s" % (x, x_unit[2])

fig_size = [8, 8]
fig_size_wide = [16, 8]
tight_layout = False

x_m = [i for i in range(1, 17)]
#y_rs_sign = [0.678, 0.733, 0.842, 0.923, 1.201, 1.669, 2.849, 4.706, 8.209, 18.922, 33.353, 63.038, 121.048, 244.282, 624.518, 1045.035]
#y_rs_verif = [0.585, 0.603, 0.656, 0.670, 0.682, 1.050, 0.729, 0.673, 0.684, 0.683, 0.702, 0.695, 0.688, 0.701, 1.011, 0.710]
y_rs_sign = [0 for i in range(1, 17)]
y_rs_verif = [0 for i in range(1, 17)]

with open("rs_benchmark_results.out", "r") as f:
    column_names = f.readline().strip().split(",")
    for i, line in enumerate(f):
        vals = line.strip().split(",")
        if int(x_m[i] != int(vals[0]) or len(vals) != 3):
            print("Error in input file")
            exit(0)
        y_rs_sign[i] = float(vals[1])
        y_rs_verif[i] = float(vals[2])

print(y_rs_sign)
print(y_rs_verif)

#y_as_fill = [3.640, 7.861, 16.459, 39.720, 75.515, 182.534, 309.605, 661.855, 1499.275, 3569.076, 6582.784, 14468.181, 27361.288, 63752.537, 124624.051, 238438.082]
#y_as_lut_size = [344, 680, 1352, 2696, 5381, 10760, 21512, 43012, 86011, 172022, 344039, 688051, 1376108, 2752223, 5504416, 11008758]
#y_as_sign = [1.011, 1.093, 1.130, 1.130, 1.120, 1.122, 1.132, 1.104, 1.111, 1.168, 1.099, 1.136, 1.181, 1.184, 1.162, 1.120]
#y_as_verif = [0.635, 0.630, 0.655, 0.635, 0.680, 0.653, 0.649, 0.693, 0.655, 0.646, 0.642, 0.660, 0.749, 0.686, 0.672, 0.649]
y_as_fill, y_as_lut_size, y_as_sign, y_as_verif = ([0 for _ in range(1, 17)] for _ in range(4))

with open("as_var_M_benchmark_results.out", "r") as f:
    column_names = f.readline().strip().split(",")
    for i, line in enumerate(f):
        vals = line.strip().split(",")
        if int(x_m[i] != int(vals[0]) or len(vals) != 6):
            print("Error in input file")
            exit(0)
        const_C = int(vals[1])
        y_as_fill[i] = float(vals[2])
        y_as_lut_size[i] = int(vals[3])
        y_as_sign[i] = float(vals[4])
        y_as_verif[i] = float(vals[5])

print(y_as_fill)
print(y_as_lut_size)
print(y_as_sign)
print(y_as_verif)

x_C = [i for i in range(3, 21)]
#y_as_fill_const_m = [454.498, 757.061, 685.654, 891.153, 921.880, 1058.048, 985.858, 1286.219, 1278.191, 1367.442, 1381.675, 1410.611, 1629.252, 1622.521, 1857.896, 1814.492, 1916.452, 2216.010]
#y_as_lut_size_const_m = [26630, 34822, 43013, 51204, 59390, 67591, 75781, 83969, 92158, 100348, 108541, 116730, 124921, 133114, 141301, 149505, 157691, 165878]
#y_as_sign_const_m = [1.093, 1.071, 1.079, 1.112, 1.077, 1.083, 1.082, 1.090, 1.072, 1.111, 1.074, 1.078, 1.079, 1.089, 1.191, 1.119, 1.084, 1.090]
#y_as_verif_const_m = [0.637, 0.644, 0.661, 0.646, 0.649, 0.671, 0.636, 0.636, 0.645, 0.650, 0.643, 0.664, 0.646, 0.644, 0.642, 0.645,0.646,  0.672]
y_as_fill_const_m, y_as_lut_size_const_m, y_as_sign_const_m, y_as_verif_const_m = ([0 for _ in range(3, 21)] for _ in range(4))

with open("as_var_C_benchmark_results.out", "r") as f:
    column_names = f.readline().strip().split(",")
    for i, line in enumerate(f):
        vals = line.strip().split(",")
        if int(x_C[i] != int(vals[1]) or len(vals) != 6):
            print("Error in input file")
            exit(0)
        const_m = int(vals[0])
        y_as_fill_const_m[i] = float(vals[2])
        y_as_lut_size_const_m[i] = int(vals[3])
        y_as_sign_const_m[i] = float(vals[4])
        y_as_verif_const_m[i] = float(vals[5])

print(y_as_fill_const_m)
print(y_as_lut_size_const_m)
print(y_as_sign_const_m)
print(y_as_verif_const_m)

print(len(x_C), len(y_as_fill_const_m), len(y_as_lut_size_const_m), len(y_as_sign_const_m), len(y_as_verif_const_m))

#y_baseline_sign = [0.315 for x in range(1, 17)]
#y_baseline_verif = [0.288 for x in range(1, 17)]
y_baseline_sign, y_baseline_verif = ([0 for _ in range(1, 17)] for _ in range(2))

with open("ecdsa_benchmark_results.out", "r") as f:
    column_names = f.readline().strip().split(",")
    for i, line in enumerate(f):
        vals = line.strip().split(",")
        y_baseline_sign[i] = float(vals[0])
        y_baseline_verif[i] = float(vals[1])

y_baseline_sign = [y_baseline_sign[0] for x in range(1, 17)]
y_baseline_verif = [y_baseline_verif[0] for x in range(1, 17)]

print(y_baseline_sign)
print(y_baseline_verif)


lut_x = [i for i in range(1, 17)]
lut_C = 5
lut_entries = []

with open("lut_balance_benchmark_results.out", "r") as f:
    column_names = f.readline().strip().split(",")
    for i, line in enumerate(f):
        vals = line.strip().split("[")[0].split(",")[:-1]
        entries = line.strip().split("[")[1].strip("]").split(",")
        if int(lut_x[i] != int(vals[0]) or len(vals) != 2):
            print("Error in input file")
            exit(0)
        lut_entries.append([int(e) for e in entries])

fig, axes = plt.subplots(2, 1, figsize=fig_size, tight_layout=tight_layout)
#axes[0,1].set_axis_off()
#axes[1,1].set_axis_off()

xdata = x_m
ydata = [y_rs_sign, y_rs_verif]
ylabel = ["Time (log scale)", "Time"]
ylim = [(0.1, 10 ** 4), (0, 2)]
scale = ["log", "linear"]
titles = ["Rejection Sampling SIGN [+ ENCRYPT] time (average from n = 1000)", "Rejection Sampling VERIFY [+ DECRYPT] time (average from n = 1000)"]
fmt = [time_lossy_fmt, time_fmt]
for i in range(2):
    ax = axes[i]
    #fig = plt.figure(figsize=[7,5])
    #ax = f

    # set the grid on
    ax.grid('on')
    ax.set_axisbelow(True)

    # add more ticks
    ax.set_xticks(np.arange(17)[1:])

    ax.set_yscale(scale[i])
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(fmt[i]))
    l = ax.scatter(xdata, ydata[i], color="red")
    ax.plot(xdata, ydata[i], color="red", linestyle="dashed", linewidth=0.5)

    # set the basic properties
    ax.set_xlabel('Anamorphic message length [bits]')
    ax.set_ylabel(ylabel[i])
    ax.set_title(titles[i])

    # set the limits
    ax.set_xlim(1, 17)
    ax.set_ylim(*ylim[i])

    # tweak the axis labels
    xlab = ax.xaxis.get_label()
    ylab = ax.yaxis.get_label()

    xlab.set_style('italic')
    xlab.set_size(10)
    ylab.set_style('italic')
    ylab.set_size(10)

    # tweak the title
    ttl = ax.title
    ttl.set_weight('bold')

fig.savefig("RS.png")

fig, axes = plt.subplots(2, 2, figsize=fig_size_wide, tight_layout=tight_layout)
xdata = x_m
ydata = [y_as_sign, y_as_verif, y_as_fill,  y_as_lut_size]
ylabel = ["Time", "Time", "Time (log scale)",  "Size (log scale)"]
ylim = [(0, 2), (0, 2), (0.1, 10 ** 6), (100, 10 ** 8)]
scale = ["linear", "linear", "log",  "log"]
fig.suptitle(f'Advance Sampling benchmarks with variable m, constant C = {const_C}', fontsize=16)

titles = ["Advance Sampling SIGN [+ INSERT + ENCRYPT] time (average from n = 1000)", 
          "Advance Sampling VERIFY [+ DECRYPT] time (average from n = 1000)",
          "Advance Sampling FILL time",
          "Advance Sampling LUT size"]
fmt = [time_fmt, time_fmt, time_fmt, sizeof_fmt]
for i in range(4):
    ax = axes[i%2][i//2]
    #fig = plt.figure(figsize=[7,5])
    #ax = f

    # set the grid on
    ax.grid('on')
    ax.set_axisbelow(True)

    # add more ticks
    ax.set_xticks(np.arange(17)[1:])

    ax.set_yscale(scale[i])
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(fmt[i]))
    l = ax.scatter(xdata, ydata[i], color="blue")
    ax.plot(xdata, ydata[i], color="blue", linestyle="dashed", linewidth=0.5)

    # set the basic properties
    ax.set_xlabel('Anamorphic message length [bits]')
    ax.set_ylabel(ylabel[i])
    ax.set_title(titles[i])

    # set the limits
    ax.set_xlim(1, 17)
    ax.set_ylim(*ylim[i])

    # tweak the axis labels
    xlab = ax.xaxis.get_label()
    ylab = ax.yaxis.get_label()

    xlab.set_style('italic')
    xlab.set_size(10)
    ylab.set_style('italic')
    ylab.set_size(10)

    # tweak the title
    ttl = ax.title
    ttl.set_weight('bold')

fig.savefig("AS_m.png")

fig, axes = plt.subplots(2, 2, figsize=fig_size_wide, tight_layout=tight_layout)
xdata = x_C
ydata = [y_as_sign_const_m, y_as_verif_const_m, y_as_fill_const_m,  y_as_lut_size_const_m]
ylabel = ["Time", "Time", "Time",  "Size"]
ylim = [(0, 2), (0, 2), (0, 2500), (25000, 170000)]
scale = ["linear", "linear", "linear",  "linear"]
fig.suptitle(f'Advance Sampling benchmarks with variable C, constant m = {const_m}', fontsize=16)

titles = ["Advance Sampling SIGN [+ INSERT + ENCRYPT] time (average from n = 1000)", 
          "Advance Sampling VERIFY [+ DECRYPT] time (average from n = 1000)",
          "Advance Sampling FILL time",
          "Advance Sampling LUT size"]
fmt = [time_fmt, time_fmt, time_fmt, sizeof_fmt]
for i in range(4):
    ax = axes[i%2][i//2]
    #fig = plt.figure(figsize=[7,5])
    #ax = f

    # set the grid on
    ax.grid('on')
    ax.set_axisbelow(True)

    # add more ticks
    ax.set_xticks(np.arange(21)[1:])

    ax.set_yscale(scale[i])
    ax.yaxis.set_major_formatter(ticker.FuncFormatter(fmt[i]))
    l = ax.scatter(xdata, ydata[i], color="navy")
    ax.plot(xdata, ydata[i], color="navy", linestyle="dashed", linewidth=0.5)

    # set the basic properties
    ax.set_xlabel('Initial amount of elements in the Lookup Table C')
    ax.set_ylabel(ylabel[i])
    ax.set_title(titles[i])

    # set the limits
    ax.set_xlim(3, 21)
    ax.set_ylim(*ylim[i])

    # tweak the axis labels
    xlab = ax.xaxis.get_label()
    ylab = ax.yaxis.get_label()

    xlab.set_style('italic')
    xlab.set_size(10)
    ylab.set_style('italic')
    ylab.set_size(10)

    # tweak the title
    ttl = ax.title
    ttl.set_weight('bold')

fig.savefig("AS_C.png")

# all plots
fig, axes = plt.subplots(2, 1, figsize=fig_size, tight_layout=tight_layout)
#axes[0,1].set_axis_off()
#axes[1,1].set_axis_off()

ax = axes[0]

# set the grid on
ax.grid('on')
ax.set_axisbelow(True)

# add more ticks
ax.set_xticks(np.arange(17)[1:])

ax.set_yscale("log")
ax.yaxis.set_major_formatter(ticker.FuncFormatter(time_lossy_fmt))

xdata = x_m
l1 = ax.scatter(xdata, y_rs_sign, color="red", label ='Rejection Sampling')
l2 = ax.plot(xdata, y_rs_sign, color="red", linestyle="dashed", linewidth=0.5)

l3 = ax.scatter(xdata, y_as_sign, color="blue", label='Advance Sampling', marker="v")
l4 = ax.plot(xdata, y_as_sign, color="blue", linestyle="dashed", linewidth=0.5)

l5 = ax.plot(xdata, y_baseline_sign, color="green", linewidth=2.5, label='Pure ECDSA')

#ax.legend([l1, l3, l5], [, 'Advance Sampling', 'Pure ECDSA'])
ax.legend()

# set the basic properties
ax.set_xlabel('Anamorphic message length [bits]')
ax.set_ylabel("Time (log scale)")
ax.set_title("RS, AS and pure ECDSA SIGN time")

# set the limits
ax.set_xlim(1, 17)
ax.set_ylim((0.1, 10 ** 6))

# tweak the axis labels
xlab = ax.xaxis.get_label()
ylab = ax.yaxis.get_label()

xlab.set_style('italic')
xlab.set_size(10)
ylab.set_style('italic')
ylab.set_size(10)

# tweak the title
ttl = ax.title
ttl.set_weight('bold')

ax = axes[1]

# set the grid on
ax.grid('on')
ax.set_axisbelow(True)

# add more ticks
ax.set_xticks(np.arange(17)[1:])

ax.set_yscale("linear")
ax.yaxis.set_major_formatter(ticker.FuncFormatter(time_fmt))

l1 = ax.scatter(xdata, y_rs_verif, color="red", label ='Rejection Sampling')
l2 = ax.plot(xdata, y_rs_verif, color="red", linestyle="dashed", linewidth=0.5)

l3 = ax.scatter(xdata, y_as_verif, color="blue", label='Advance Sampling', marker="v")
l4 = ax.plot(xdata, y_as_verif, color="blue", linestyle="dashed", linewidth=0.5)

l5 = ax.plot(xdata, y_baseline_verif, color="green", linewidth=2.5, label='Pure ECDSA')

ax.legend()

# set the basic properties
ax.set_xlabel('Anamorphic message length [bits]')
ax.set_ylabel("Time")
ax.set_title("RS, AS and pure ECDSA VERIFY time")

# set the limits
ax.set_xlim(1, 17)
ax.set_ylim((0, 2))

# tweak the axis labels
xlab = ax.xaxis.get_label()
ylab = ax.yaxis.get_label()

xlab.set_style('italic')
xlab.set_size(10)
ylab.set_style('italic')
ylab.set_size(10)

# tweak the title
ttl = ax.title
ttl.set_weight('bold')

fig.savefig("All.png")
#plt.show()

fig, axes = plt.subplots(1, 1, figsize=fig_size_wide, tight_layout=tight_layout)
#axes[0,1].set_axis_off()

ax = axes
bins = [i for i in range(0, lut_C*2+2)]
print(bins)
plt.xticks(bins, bins, size=15)
plt.yticks(size=15)
values, bins, bars = ax.hist(lut_entries[15], alpha=1, histtype='barstacked', align="left", rwidth=0.8, bins=bins, linewidth=1.5, edgecolor='black', color='blueviolet')

# set the basic properties
ax.set_xlabel('Number of entries in the Lookup Table row')
ax.set_ylabel("Count")
ax.set_title("Lookup Table entries distribution for m = 16, C = 5, n = 100 000", size=20)

# tweak the axis labels
xlab = ax.xaxis.get_label()
ylab = ax.yaxis.get_label()

xlab.set_style('italic')
xlab.set_size(18)
ylab.set_style('italic')
ylab.set_size(18)

# tweak the title
ttl = ax.title
ttl.set_weight('bold')

# add labels

plt.bar_label(bars, fontsize=20, color='black')

fig.savefig("LUT_hist.png")