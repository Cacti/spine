# SPDX-License-Identifier: LGPL-2.1-or-later
NR == 1 || $1 <= warmup || $5 != 0 || $6 != expected_rows { next }
{
	n++; x = $2; y = $3
	sx += x; sy += y; sxx += x * x; sxy += x * y
	if (n == 1) { first = y; x0 = x; min = y; max = y }
	last = y; x1 = x
	if (y < min) min = y
	if (y > max) max = y
}
END {
	if (n < 2) { print n + 0, 0, 0, 0, 0, 0, 0, 0; exit }
	d = n * sxx - sx * sx
	slope = d == 0 ? 0 : (n * sxy - sx * sy) / d
	printf "%d %.1f %.0f %d %d %d %d %.0f\n", n, slope * 3600,
		slope * (x1 - x0), first, last, min, max, sy / n
}
