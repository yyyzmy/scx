#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# ============================================================================
# isc_fit.py — SYNPA 线性回归模型拟合器（纯 Python, 无依赖）
#
# 读取 isc_stat.sh 生成的训练数据集 CSV, 拟合全局共用的一组系数:
#
#   C_smt(i,j) = a + b*C_st(i) + g*C_st(j) + r*C_st(i)*C_st(j)
#
# 对 3 个类别 (FEstalls, BEstalls, DIcycles) 各拟合一个方程, 共 12 个系数。
# 所有应用对共用同一组系数 —— 应用差异全部体现在特征 C_st 中。
#
# 用法:
#   python3 isc_fit.py isc_dataset.csv              # 基本拟合
#   python3 isc_fit.py isc_dataset.csv --show 20    # 显示前 20 条样本对照
#   python3 isc_fit.py isc_dataset.csv --ridge 1e-6 # 岭回归正则(病态数据时)
#   python3 isc_fit.py isc_dataset.csv --loo        # 留一交叉验证(样本充足时)
#
# 输出:
#   1. 数据概况与充分性检查
#   2. 每类别的系数 / R^2 / RMSE
#   3. 训练样本 实测 vs 预测 对照
#   4. 可直接嵌入 BPF 的 C 代码块
# ============================================================================

import argparse
import csv
import sys

CATS = ("FEstalls", "BEstalls", "DIcycles")
PARAMS_PER_CAT = 4  # a, b, g, r


# ---------------------------------------------------------------------------
# 数据读取
# ---------------------------------------------------------------------------
def read_dataset(path):
    """返回 (st, samples):
       st:     {app: {类别: 值}}                —— ST 特征
       samples:[(app_i, app_j, {类别: 实测值})] —— SMT 样本
    """
    st, samples = {}, []
    try:
        f = open(path, newline="")
    except OSError as e:
        sys.exit("[错误] 无法打开 %s: %s" % (path, e))
    with f:
        for row in csv.DictReader(f):
            mode = (row.get("mode") or "").strip()
            app = (row.get("app") or "").strip()
            if not app:
                continue
            try:
                if mode == "st":
                    st[app] = {c: float(row[c]) for c in CATS}
                elif mode == "smt":
                    co = (row.get("co_runner") or "").strip()
                    samples.append((app, co, {c: float(row[c]) for c in CATS}))
            except (KeyError, ValueError) as e:
                print("[警告] 跳过格式异常行: %r (%s)" % (row, e), file=sys.stderr)
    return st, samples


def build_xy(samples, st, cat):
    """把 smt 样本转为 (特征矩阵, 目标向量), 跳过缺 ST 特征的样本"""
    A, y, tags = [], [], []
    for app, co, meas in samples:
        if app not in st or co not in st:
            continue
        xi = st[app][cat]
        xj = st[co][cat]
        A.append([1.0, xi, xj, xi * xj])
        y.append(meas[cat])
        tags.append("%s+%s" % (app, co))
    return A, y, tags


# ---------------------------------------------------------------------------
# 最小二乘: 正规方程 + 高斯消元(列主元), 可选岭回归
# ---------------------------------------------------------------------------
def lstsq(A, y, ridge=0.0):
    n = len(A[0])
    m = len(A)
    # (A^T A + ridge*I) x = A^T y
    M = [[sum(A[k][i] * A[k][j] for k in range(m)) + (ridge if i == j else 0.0)
          for j in range(n)] for i in range(n)]
    v = [sum(A[k][i] * y[k] for k in range(m)) for i in range(n)]
    # 高斯消元(列主元)
    for col in range(n):
        p = max(range(col, n), key=lambda r: abs(M[r][col]))
        if abs(M[p][col]) < 1e-14:
            continue  # 该方向奇异, 回代时 x[col] 自然置 0
        M[col], M[p] = M[p], M[col]
        v[col], v[p] = v[p], v[col]
        for r in range(col + 1, n):
            fac = M[r][col] / M[col][col]
            if fac == 0.0:
                continue
            for c in range(col, n):
                M[r][c] -= fac * M[col][c]
            v[r] -= fac * v[col]
    x = [0.0] * n
    for i in range(n - 1, -1, -1):
        if abs(M[i][i]) < 1e-14:
            continue
        x[i] = (v[i] - sum(M[i][j] * x[j] for j in range(i + 1, n))) / M[i][i]
    return x


def predict(coef, xi, xj):
    a, b, g, r = coef
    return a + b * xi + g * xj + r * xi * xj


def r2_rmse(A, y, coef):
    ys = [sum(A[k][j] * coef[j] for j in range(len(coef))) for k in range(len(A))]
    if not y:
        return 0.0, 0.0
    mean = sum(y) / len(y)
    ss_tot = sum((t - mean) ** 2 for t in y)
    ss_res = sum((t - p) ** 2 for t, p in zip(y, ys))
    r2 = 1.0 - ss_res / ss_tot if ss_tot > 0 else (1.0 if ss_res <= 0 else 0.0)
    rmse = (ss_res / len(y)) ** 0.5
    return r2, rmse


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="SYNPA 回归模型拟合器")
    ap.add_argument("csvfile", help="isc_stat.sh -m all 生成的数据集 CSV")
    ap.add_argument("--ridge", type=float, default=1e-9,
                    help="岭回归正则系数 (默认 1e-9, 病态时可加大如 1e-6)")
    ap.add_argument("--show", type=int, default=10, help="显示前 N 条样本对照")
    ap.add_argument("--loo", action="store_true",
                    help="留一交叉验证 (样本数 > 参数数时自动执行)")
    args = ap.parse_args()

    st, samples = read_dataset(args.csvfile)

    # ---- 数据概况 ----
    n_st = len(st)
    n_pair = len(set(frozenset((a, b)) for a, b, _ in samples))
    n_self = sum(1 for a, b, _ in samples if a == b)
    print("=" * 74)
    print("数据概况")
    print("=" * 74)
    print("  ST 特征应用数 : %d" % n_st)
    print("  SMT 样本数    : %d  (去重组合 %d, 其中自配对样本 %d)"
          % (len(samples), n_pair, n_self))

    usable = [(a, b, m) for a, b, m in samples if a in st and b in st]
    if len(usable) < len(samples):
        print("[警告] %d 条样本因缺少对应 ST 特征被跳过"
              % (len(samples) - len(usable)))
    if not usable:
        sys.exit("[错误] 没有可用的 (ST 特征, SMT 实测) 配对样本")

    # ---- 充分性检查 ----
    warn = []
    if len(usable) < PARAMS_PER_CAT:
        warn.append("严重欠定: 可用样本 %d < 参数 %d, 解不唯一(最小范数近似), "
                    "系数仅供参考" % (len(usable), PARAMS_PER_CAT))
    if n_pair and n_pair == sum(1 for a, b, _ in usable if a == b) // 2:
        pass
    if all(a == b for a, b, _ in usable):
        warn.append("只有自配对样本: b 与 g 两个系数在数学上不可区分 "
                    "(特征列共线), 必须补充异程序对")
    if len(usable) < PARAMS_PER_CAT * 5:
        warn.append("样本偏少 (%d < %d): 建议扩充到 6~8 个程序 "
                    "(28 对 / 56 样本) 再用于实际预测" % (len(usable), PARAMS_PER_CAT * 5))
    for w in warn:
        print("  [!] " + w)

    # ---- 拟合 ----
    print()
    print("=" * 74)
    print("拟合结果   C_smt(i,j) = a + b*C_st(i) + g*C_st(j) + r*C_st(i)*C_st(j)")
    print("=" * 74)
    coefs = {}
    for cat in CATS:
        A, y, _ = build_xy(usable, st, cat)
        coef = lstsq(A, y, args.ridge)
        r2, rmse = r2_rmse(A, y, coef)
        coefs[cat] = coef
        print("  %-9s  a=%+.6f  b=%+.6f  g=%+.6f  r=%+.6f" % (cat, *coef))
        print("             R^2 = %+.4f   RMSE = %.4f   (n=%d)" % (r2, rmse, len(y)))

    # ---- 训练样本对照 ----
    print()
    print("=" * 74)
    print("训练样本对照 (实测 vs 预测, 前 %d 条)" % args.show)
    print("=" * 74)
    print("  %-34s %-9s %8s %8s %8s" % ("组合", "类别", "实测", "预测", "误差"))
    shown = 0
    for app, co, meas in usable:
        for cat in CATS:
            if shown >= args.show:
                break
            p = predict(coefs[cat], st[app][cat], st[co][cat])
            print("  %-34s %-9s %8.4f %8.4f %+8.4f"
                  % ("%s+%s" % (app, co), cat, meas[cat], p, meas[cat] - p))
            shown += 1
        if shown >= args.show:
            break
    if len(usable) * 3 > shown:
        print("  ... (其余 %d 条省略)" % (len(usable) * 3 - shown))

    # ---- 留一交叉验证 ----
    if args.loo:
        print()
        print("=" * 74)
        print("留一交叉验证 (LOO-CV)")
        print("=" * 74)
        for cat in CATS:
            A, y, tags = build_xy(usable, st, cat)
            errs = []
            for k in range(len(A)):
                Ak = A[:k] + A[k + 1:]
                yk = y[:k] + y[k + 1:]
                if len(Ak) < PARAMS_PER_CAT:
                    continue  # 去掉一条后欠定, 跳过
                ck = lstsq(Ak, yk, args.ridge)
                errs.append(abs(y[k] - sum(A[k][j] * ck[j] for j in range(4))))
            if errs:
                print("  %-9s  n=%d  MAE=%.4f  max|err|=%.4f"
                      % (cat, len(errs), sum(errs) / len(errs), max(errs)))
            else:
                print("  %-9s  样本不足, 无法执行" % cat)

    # ---- BPF 嵌入代码 ----
    print()
    print("=" * 74)
    print("BPF 嵌入系数 (复制到 scx 调度器)")
    print("=" * 74)
    print("/* SYNPA 系数: [a, b, g, r], 拟合于 %s */" % args.csvfile)
    print("static const double synpa_coef[3][4] = {")
    for cat in CATS:
        a, b, g, r = coefs[cat]
        print("    /* %-9s */ { %+.9f, %+.9f, %+.9f, %+.9f }," % (cat, a, b, g, r))
    print("};")
    print()
    print("/* 定点版本 (x 2^20, 供 BPF 内核态无浮点计算): */")
    print("static const long synpa_coef_q20[3][4] = {")
    for cat in CATS:
        a, b, g, r = coefs[cat]
        print("    /* %-9s */ { %+d, %+d, %+d, %+d },"
              % (cat, round(a * (1 << 20)), round(b * (1 << 20)),
                 round(g * (1 << 20)), round(r * (1 << 20))))
    print("};")
    print()
    print("说明: 索引 0/1/2 对应 FEstalls/BEstalls/DIcycles;")
    print("      在线预测: C_smt = a + b*Ci + g*Cj + r*Ci*Cj (Ci/Cj 为两应用的 ST 栈)")


if __name__ == "__main__":
    main()
