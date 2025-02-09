import subprocess
import os
from datetime import datetime

def run_command(command):
    """执行命令并返回输出"""
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout, stderr = process.communicate()
    if process.returncode == 0:
        return stdout.decode('utf-8')
    else:
        raise Exception(stderr.decode('utf-8'))


def set_git_proxy(proxy_url='http://127.0.0.1:7890'):
    """检查Git是否配置了全局代理，如果没有，则设置指定的代理"""
    try:
        http_proxy = run_command('git config --global --get http.proxy')
        https_proxy = run_command('git config --global --get https.proxy')

        if not http_proxy and not https_proxy:
            print("Configuring global Git proxy...")
            run_command(f'git config --global http.proxy {proxy_url}')
            run_command(f'git config --global https.proxy {proxy_url}')
            print(f"Global Git proxy set to {proxy_url}")
        else:
            print("Global Git proxy is already configured.")
    except Exception as e:
        print(f"Error: {e}")

def git_pull():
    """拉取远程仓库的更新"""
    try:
        print("Pulling changes from remote repository...")
        output = run_command('git pull')
        print(output)
    except Exception as e:
        print(f"Error pulling changes: {e}")
        exit(1)  # 如果拉取失败，则退出脚本


def git_push(github_url):
    """将当前目录推送到GitHub"""
    try:
        # set_git_proxy()

        # git_pull()

        # 初始化Git仓库（如果尚未初始化）
        if not os.path.exists('.git'):
            run_command('git init')

        # 添加远程仓库（如果尚未添加）
        remotes = run_command('git remote')
        if 'origin' not in remotes:
            run_command(f'git remote add origin {github_url}')

        # 添加所有更改到暂存区
        run_command('git add .')

        # 提交更改
        now = datetime.now()
        commit_message = now.strftime("update-%Y%m%d-%H%M")
        run_command(f'git commit -m "{commit_message}"')

        # 推送更改到GitHub
        run_command('git push -u origin master')
        print("Successfully pushed to GitHub.")
    except Exception as e:
        print(f"Error: {e}")


# 使用示例
github_url = 'https://github.com/lmhsw1/learning_notes.git'  # 替换为你的GitHub仓库URL
git_push(github_url)

