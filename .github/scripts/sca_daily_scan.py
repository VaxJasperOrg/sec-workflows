#!/usr/bin/env python3
"""SCA 每日巡检脚本：对组织内已接入 hkvax_security.yml 的仓库逐一执行 Trivy SCA 扫描，
汇总漏洞报告写入 Job Summary，并通过钉钉推送摘要通知。

用法:
  python sca_daily_scan.py

环境变量:
  GITHUB_TOKEN       GitHub App 生成的临时 Token（必填）
  ORG_NAME           组织名称（必填）
  DINGTALK_WEBHOOK   钉钉机器人 Webhook（选填，未配置则跳过）
  DINGTALK_SECRET    钉钉机器人加签密钥（选填）
"""

import os
import sys
import json
import subprocess
import tempfile
import shutil
import time
import hmac
import hashlib
import base64
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta

import requests

GITHUB_API = "https://api.github.com"
SECURITY_WORKFLOW = "hkvax_security.yml"
RESULTS_MD = "sca_scan_results.md"


def _env(name, default=""):
    return os.environ.get(name, default).strip()


def _headers():
    token = _env("GITHUB_TOKEN")
    if not token:
        print("[!] GITHUB_TOKEN 未设置，退出。")
        sys.exit(1)
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


# ── GitHub API ──────────────────────────────────────────────

def get_all_org_repos(org_name, headers):
    """分页获取组织下所有非归档仓库。"""
    repos = []
    page = 1
    while True:
        url = f"{GITHUB_API}/orgs/{org_name}/repos?per_page=100&page={page}"
        resp = requests.get(url, headers=headers, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        if not data:
            break
        repos.extend(data)
        page += 1
    return repos


def has_security_workflow(repo, headers):
    """检查仓库是否已部署 hkvax_security.yml。"""
    url = f"{GITHUB_API}/repos/{repo['full_name']}/contents/.github/workflows/{SECURITY_WORKFLOW}"
    resp = requests.get(url, headers=headers, timeout=15)
    return resp.status_code == 200


# ── Trivy ───────────────────────────────────────────────────

def clone_repo(clone_url, token, dest_dir):
    """使用 token 鉴权 shallow clone 仓库。"""
    authenticated_url = clone_url.replace("https://", f"https://x-access-token:{token}@")
    subprocess.run(
        ["git", "clone", "--depth", "1", authenticated_url, dest_dir],
        check=True,
        capture_output=True,
        timeout=60,
    )


def run_trivy_scan(scan_dir):
    """执行 trivy fs 扫描，返回解析后的 JSON 结果。"""
    result_file = os.path.join(scan_dir, "_trivy_results.json")
    cmd = [
        "trivy", "fs",
        "--severity", "CRITICAL,HIGH",
        "--exit-code", "0",
        "--format", "json",
        "--output", result_file,
        "--scanners", "vuln,secret",
        "--ignore-unfixed",
        scan_dir,
    ]
    subprocess.run(cmd, capture_output=True, timeout=300)
    if os.path.exists(result_file):
        with open(result_file) as f:
            return json.load(f)
    return None


def count_vulns(trivy_result):
    """统计 CRITICAL / HIGH 漏洞数。"""
    critical, high = 0, 0
    if not trivy_result:
        return critical, high
    for r in trivy_result.get("Results", []) or []:
        for v in (r.get("Vulnerabilities") or []):
            sev = (v.get("Severity") or "").upper()
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
    return critical, high


# ── 钉钉 ───────────────────────────────────────────────────

def dingtalk_send(webhook, secret, title, markdown_text):
    """加签并发送钉钉 Markdown 消息。"""
    if not webhook or not secret:
        print("[*] 钉钉未配置，跳过通知。")
        return
    timestamp = str(round(time.time() * 1000))
    secret_enc = secret.encode("utf-8")
    string_to_sign = f"{timestamp}\n{secret}"
    hmac_code = hmac.new(
        secret_enc, string_to_sign.encode("utf-8"), digestmod=hashlib.sha256
    ).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    signed_url = f"{webhook}&timestamp={timestamp}&sign={sign}"
    payload = {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": markdown_text},
    }
    req = urllib.request.Request(
        signed_url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            print("[*] 钉钉响应:", resp.read().decode("utf-8"))
    except Exception as e:
        print("[!] 钉钉发送失败:", e)


# ── 主流程 ──────────────────────────────────────────────────

def main():
    org = _env("ORG_NAME")
    token = _env("GITHUB_TOKEN")
    headers = _headers()

    run_url = (
        os.environ.get("GITHUB_SERVER_URL", "")
        + "/"
        + os.environ.get("GITHUB_REPOSITORY", "")
        + "/actions/runs/"
        + os.environ.get("GITHUB_RUN_ID", "")
    )

    # 1. 获取组织所有仓库
    print(f"[*] 获取 {org} 组织下的所有仓库...")
    all_repos = get_all_org_repos(org, headers)
    print(f"[*] 共 {len(all_repos)} 个仓库（含归档）")

    # 2. 筛选已接入 hkvax_security.yml 的非归档仓库
    print("[*] 筛选已接入 hkvax_security.yml 的仓库...")
    active_repos = []
    for repo in all_repos:
        if repo.get("archived"):
            continue
        if has_security_workflow(repo, headers):
            active_repos.append(repo)
    print(f"[*] 已接入仓库: {len(active_repos)} 个")

    if not active_repos:
        print("[*] 无已接入仓库，退出。")
        return

    # 3. 逐一 shallow clone + Trivy 扫描
    scan_root = tempfile.mkdtemp(prefix="sca-daily-")
    results = []
    for idx, repo in enumerate(active_repos, 1):
        name = repo["name"]
        repo_dir = os.path.join(scan_root, name)
        print(f"[{idx}/{len(active_repos)}] 扫描 {name} ...", end=" ", flush=True)
        try:
            clone_repo(repo["clone_url"], token, repo_dir)
            trivy_data = run_trivy_scan(repo_dir)
            critical, high = count_vulns(trivy_data)
            status = "ok" if critical == 0 and high == 0 else "vuln"
            print(f"CRITICAL={critical} HIGH={high}")
        except Exception as e:
            print(f"失败: {e}")
            critical, high, status = 0, 0, "error"
        results.append({
            "name": name,
            "full_name": repo["full_name"],
            "html_url": repo["html_url"],
            "critical": critical,
            "high": high,
            "status": status,
        })
        # 清理单仓目录，节省磁盘
        shutil.rmtree(repo_dir, ignore_errors=True)

    shutil.rmtree(scan_root, ignore_errors=True)

    # 4. 汇总统计
    vuln_repos = [r for r in results if r["status"] == "vuln"]
    error_repos = [r for r in results if r["status"] == "error"]
    total_critical = sum(r["critical"] for r in results)
    total_high = sum(r["high"] for r in results)
    bj_tz = timezone(timedelta(hours=8))
    now_bj = datetime.now(bj_tz).strftime("%Y-%m-%d %H:%M")

    # 5. 生成 Job Summary Markdown
    md = [
        f"### SCA 每日巡检报告",
        "",
        f"- **扫描时间**: {now_bj} (北京时间)",
        f"- **扫描范围**: {len(results)} 个已接入仓库",
        f"- **发现漏洞仓库**: {len(vuln_repos)} 个",
        f"- **漏洞统计**: CRITICAL {total_critical} 个, HIGH {total_high} 个",
        "",
    ]

    if vuln_repos:
        md += [
            "#### 存在漏洞的仓库",
            "",
            "| 仓库 | CRITICAL | HIGH | 链接 |",
            "| --- | --- | --- | --- |",
        ]
        for r in sorted(vuln_repos, key=lambda x: (x["critical"], x["high"]), reverse=True):
            md.append(f"| {r['name']} | {r['critical']} | {r['high']} | [{r['name']}]({r['html_url']}) |")
        md.append("")

    if error_repos:
        md += [
            "#### 扫描失败的仓库",
            "",
            "| 仓库 | 链接 |",
            "| --- | --- |",
        ]
        for r in error_repos:
            md.append(f"| {r['name']} | [{r['name']}]({r['html_url']}) |")
        md.append("")

    if not vuln_repos and not error_repos:
        md.append("> 所有仓库均未发现 CRITICAL / HIGH 级别漏洞，扫描全部成功。")

    report_md = "\n".join(md)
    with open(RESULTS_MD, "w") as f:
        f.write(report_md)
    print(f"[*] 报告已写入 {RESULTS_MD}")

    # 6. 钉钉通知（存在漏洞或扫描失败时推送）
    webhook = _env("DINGTALK_WEBHOOK")
    secret = _env("DINGTALK_SECRET")
    if vuln_repos or error_repos:
        title = "【SCA 每日巡检报告】"
        text = (
            f"### SCA 每日巡检报告\n\n"
            f"- **扫描时间**: {now_bj} (北京时间)\n"
            f"- **扫描范围**: {len(results)} 个已接入仓库\n"
            f"- **发现漏洞仓库**: {len(vuln_repos)} 个"
            f" (CRITICAL: {total_critical}, HIGH: {total_high})\n"
        )
        if error_repos:
            text += f"- **扫描失败**: {len(error_repos)} 个\n"
        text += f"\n[查看完整报告]({run_url})"
        dingtalk_send(webhook, secret, title, text)
    else:
        print("[*] 全部通过，跳过钉钉通知。")


if __name__ == "__main__":
    main()
