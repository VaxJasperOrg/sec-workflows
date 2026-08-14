#!/usr/bin/env python3
"""组织级安全检查 workflow 自动巡检 / 自动注入脚本。

用法:
  python auto_inject.py scan    # 仅扫描：识别未部署 security.yml 的仓库，scan 模式下推送钉钉告警
  python auto_inject.py inject  # 注入：为扫描结果中未部署的仓库自动注入 security.yml，并推送结果

环境变量:
  GITHUB_TOKEN       GitHub App 生成的临时 Token（必填）
  ORG_NAME           组织名称（必填）
  DINGTALK_WEBHOOK   钉钉机器人 Webhook（未配置则跳过告警）
  DINGTALK_SECRET    钉钉机器人加签密钥（未配置则跳过告警）
  MODE               本次运行模式 scan / inject（默认 scan；inject 时扫描阶段不告警）
  FORCE_UPDATE       inject 模式下为 true 时，强制覆盖已存在的 security.yml
"""

import base64
import hashlib
import hmac
import json
import os
import sys
import time
import urllib.parse

import requests

# GHE 私有部署请改为 https://<ghe-domain>/api/v3
GITHUB_API = "https://api.github.com"
WORKFLOW_PATH = ".github/workflows/hkvax_security.yml"
SCAN_RESULTS_FILE = "scan_results.json"

WORKFLOW_TEMPLATE = """name: Security Gate

on:
  pull_request:
    branches: [ "main", "master", "release/*" ]             # 这里需要根据实际情况修改

jobs:
  call-security-central:
    name: Central Security Gate
    uses: {org}/sec-workflows/.github/workflows/sonar_sast_check.yml@main
    secrets: inherit
"""


def _env(name, default=""):
    return os.environ.get(name, default).strip()


def _headers():
    token = _env("GITHUB_TOKEN")
    if not token:
        print("[!] 错误：未获取到有效的 GITHUB_TOKEN！")
        sys.exit(1)
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
    }


def _result_file():
    return os.path.join(_env("GITHUB_WORKSPACE", "."), SCAN_RESULTS_FILE)


def get_all_org_repos(org_name, headers):
    """分页获取组织下的所有仓库"""
    repos = []
    page = 1
    while True:
        url = f"{GITHUB_API}/orgs/{org_name}/repos?per_page=100&page={page}&type=all"
        res = requests.get(url, headers=headers)
        if res.status_code != 200:
            print(f"[!] 获取仓库列表失败: {res.status_code} - {res.text}")
            break
        data = res.json()
        if not data:
            break
        repos.extend(data)
        page += 1
    return repos


def is_scannable(repo):
    """跳过归档仓库与中央安全仓库本身"""
    return not repo.get("archived", False) and repo["name"] != "sec-workflows"


def has_security_workflow(org_name, repo_name, headers):
    url = f"{GITHUB_API}/repos/{org_name}/{repo_name}/contents/{WORKFLOW_PATH}"
    return requests.get(url, headers=headers).status_code == 200


def scan_org(org_name, headers):
    """扫描所有仓库并写入结果文件，返回 (缺失仓库列表, 仓库总数, 跳过数)"""
    print(f"[*] 开始扫描组织 '{org_name}' 的所有仓库...")
    all_repos = get_all_org_repos(org_name, headers)
    print(f"[*] 共计检测到 {len(all_repos)} 个仓库。")

    results, missing, skipped = [], [], 0
    for repo in all_repos:
        if not is_scannable(repo):
            skipped += 1
            continue

        repo_name = repo["name"]
        deployed = has_security_workflow(org_name, repo_name, headers)
        record = {
            "name": repo_name,
            "default_branch": repo.get("default_branch", "main"),
            "html_url": repo.get("html_url", f"https://github.com/{org_name}/{repo_name}"),
            "has_security": deployed,
        }
        results.append(record)
        if not deployed:
            missing.append(record)
            print(f"[!] [{repo_name}] 未部署 security.yml")
        time.sleep(0.2)

    with open(_result_file(), "w", encoding="utf-8") as f:
        json.dump(results, f, ensure_ascii=False)
    print(f"[*] 扫描结果已写入 {_result_file()}")
    print(f"[*] 扫描完成！检测到 {len(all_repos)} 个仓库，跳过 {skipped} 个，"
          f"未部署安全检查 workflow 的仓库 {len(missing)} 个。")
    return missing, len(all_repos), skipped


def inject_workflow(org_name, record, force_update, headers):
    """向单个仓库写入 hkvax_security.yml，返回 (状态, 描述)"""
    url = f"{GITHUB_API}/repos/{org_name}/{record['name']}/contents/{WORKFLOW_PATH}"
    res = requests.get(url, headers=headers)
    sha = None
    if res.status_code == 200:
        if not force_update:
            return "skipped", "已存在 hkvax_security.yml"
        sha = res.json().get("sha")

    payload = {
        "message": "chore: [Security Team] Auto-inject security gate workflow",
        "content": base64.b64encode(
            WORKFLOW_TEMPLATE.format(org=org_name).encode("utf-8")
        ).decode("utf-8"),
        "branch": record["default_branch"],
    }
    if sha:
        payload["sha"] = sha

    put_res = requests.put(url, headers=headers, json=payload)
    if put_res.status_code in [200, 201]:
        return "updated" if sha else "created", "成功注入/更新 security.yml"
    if put_res.status_code == 409:
        return "skipped", "冲突或无初始 commit（空仓库）"
    return "failed", f"HTTP {put_res.status_code}"


def inject_all(org_name, headers):
    """读取扫描结果并为目标仓库注入，返回 (目标数, 成功仓库列表, 失败列表)"""
    if not os.path.exists(_result_file()):
        print(f"[!] 未找到扫描结果文件 {SCAN_RESULTS_FILE}，请先运行扫描步骤。")
        sys.exit(1)

    with open(_result_file(), encoding="utf-8") as f:
        results = json.load(f)

    force_update = _env("FORCE_UPDATE", "false").lower() == "true"
    targets = [r for r in results if not r["has_security"] or force_update]
    print(f"[*] 注入模式：扫描仓库 {len(results)} 个，本次注入目标 {len(targets)} 个 "
          f"(force_update={force_update})。")

    success, failed = [], []
    for record in targets:
        status, desc = inject_workflow(org_name, record, force_update, headers)
        if status == "failed" or status == "skipped":
            failed.append((record["name"], desc))
            print(f"[!] [{record['name']}] 注入失败：{desc}")
        else:
            success.append(record["name"])
            print(f"[+] [{record['name']}] {desc}")
        time.sleep(0.2)

    print(f"[*] 组织级安全注入完成！成功 {len(success)} 个，失败 {len(failed)} 个。")
    return len(targets), success, failed


def dingtalk_send(title, markdown_text):
    """钉钉加签并推送 markdown 消息"""
    webhook = _env("DINGTALK_WEBHOOK")
    secret = _env("DINGTALK_SECRET")
    if not webhook or not secret:
        print("[!] 未配置 DINGTALK_WEBHOOK / DINGTALK_SECRET，跳过钉钉告警。")
        return

    timestamp = str(round(time.time() * 1000))
    string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
    hmac_code = hmac.new(secret.encode("utf-8"), string_to_sign, digestmod=hashlib.sha256).digest()
    sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
    url = f"{webhook}&timestamp={timestamp}&sign={sign}"

    payload = {
        "msgtype": "markdown",
        "markdown": {"title": title, "text": markdown_text},
    }
    req = requests.post(url, json=payload, timeout=30)
    resp = req.json() if req.status_code == 200 else None
    if resp and resp.get("errcode") == 0:
        print("[+] 钉钉告警发送成功！")
    else:
        print(f"[!] 钉钉告警发送失败: {req.status_code} - {req.text}")


def send_scan_alert(org_name, total, skipped, missing):
    """扫描模式：存在未部署仓库时推送告警"""
    repo_list = "\n".join(f"- [{m['name']}]({m['html_url']})" for m in missing)
    text = (
        "### 安全检查 Workflow 未部署告警\n"
        "\n"
        f"- **触发时间**: {time.strftime('%Y-%m-%d %H:%M:%S')} \n"
        f"- **组织**: `{org_name}` \n"
        f"- **本次巡检发现的仓库总数**: {total} \n"
        f"- **已跳过(归档/中央仓库)**: {skipped} \n"
        f"- **未部署安全检查 workflow 的仓库数**: {len(missing)} \n"
        "\n"
        f"**未部署仓库清单**: \n{repo_list}"
    )
    dingtalk_send("【安全巡检】存在未部署安全检查 Workflow 的仓库", text)


def send_inject_report(org_name, total, success, failed):
    """注入模式：仅当存在注入失败时，推送失败告警"""
    text = (
        "### 安全检查 Workflow 自动注入情况\n"
        "\n"
        f"- **触发时间**: {time.strftime('%Y-%m-%d %H:%M:%S')} \n"
        f"- **组织**: `{org_name}` \n"
        f"- **注入目标仓库数**: {total} \n"
        f"- **注入成功**: {len(success)} \n"
        f"- **注入失败**: {len(failed)} \n"
    )
    if success:
        text += "\n**注入成功仓库**:\n" + "\n".join(f"- `{name}`" for name in success)
    if failed:
        text += "\n**注入失败仓库**:\n" + "\n".join(f"- `{name}`（{reason}）" for name, reason in failed)
    dingtalk_send("【安全巡检】Workflow 注入失败", text)


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "scan"
    org_name = _env("ORG_NAME")
    if not org_name:
        print("[!] 错误：未获取到 ORG_NAME！")
        sys.exit(1)
    headers = _headers()

    if mode == "inject":
        total, success, failed = inject_all(org_name, headers)
        # 仅当存在注入失败时推送告警；全部成功则静默
        if failed:
            send_inject_report(org_name, total, success, failed)
    else:
        missing, total, skipped = scan_org(org_name, headers)
        # inject 模式由注入步骤推送结果，此处不重复告警
        if _env("MODE", "scan") != "inject" and missing:
            send_scan_alert(org_name, total, skipped, missing)


if __name__ == "__main__":
    main()
