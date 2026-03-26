import argparse
import glob
import json
import os
import re
import stat
import subprocess
import sys
from datetime import datetime

def main(mode="full"):
    def run(args, timeout=30): #запуск системных команд
        #если команда относится к другой части аудита — пропуск
        try:
            cmd_cat = cmd_category(args)
            if cmd_cat not in allowed_categories:
                return ""
        except Exception:
            #в случае неожиданных входных данных просто пробуем запустить
            pass

        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=timeout) #выполняем команду
            out = (r.stdout or "").strip()
            err = (r.stderr or "").strip()
            #для аудита полезны и stdout, и stderr
            if out and err:
                return out + "\n" + err
            return out or err or ""
        except Exception:
            return ""

    def push(type, problem, details, fix, evidence=None, category="misc"):
        item = {
            "тип": type,  #ошибка или предупреждение
            "проблема": problem,
            "детали": details,
            "рекомендация": fix,
            "category": category,
        }
        #в поле evidence кладем “сырье/подтверждение” только когда оно реально есть.
        if evidence is not None:
            item["evidence"] = evidence
        findings.append(item)

    def first_lines(text, n=5): #функция для вывода первых n строк
        lines = []
        for line in text.splitlines():
            line = line.strip()
            if line:
                lines.append(line)
            if len(lines) >= n:
                break
        return lines

    t = datetime.now().strftime("%Y-%m-%d %H:%M:%S") #время
    findings = []

    print("Автоаудит Linux")
    print("Время:", t)
    if os.geteuid() != 0:
        print("Запущено без sudo. Что-то может не вывестись.\n") #выводим сообщение о том, что запущено без sudo

    normalized_mode = (mode or "full").strip().lower()
    if normalized_mode in ("network",):
        allowed_categories = {"network"}
    elif normalized_mode in ("fs", "filesystem", "файлы"):
        allowed_categories = {"fs"}
    elif normalized_mode in ("admin", "ssh", "sudo"):
        allowed_categories = {"admin"}
    else:
        allowed_categories = {"fs", "network", "admin", "misc"}

    def cmd_category(args): #функция для определения категории команды
        if not args:
            return "misc"
        if not isinstance(args, (list, tuple)):
            return "misc"
        if len(args) == 0:
            return "misc"
        cmd = str(args[0])
        if cmd == "find":
            return "fs"
        if cmd == "ss":
            return "network"
        if cmd == "dpkg-query":
            return "network"
        if cmd == "uname":
            return "admin"
        return "misc"

#права (777/666) проверка
    for d in ("/etc", "/var", "/home"):
        out = run(["find", d, "-type", "f", "-perm", "-0777", "-print"], timeout=30) #команда поиска файлов с правами 777
        if out:
            samples = first_lines(out)
            push(
                "ошибка",
                "Опасные права 777",
                "Где: "
                + d
                + "\nПримеры:\n- "
                + "\n- ".join(samples),
                "снизить права (обычно chmod 644 для файлов, chmod 755 для каталогов).",
                evidence=samples,
                category="fs",
            )
#проверка прав 666
        out = run(["find", d, "-type", "f", "-perm", "-0666", "-print"], timeout=30) #команда поиска файлов с правами 666
        if out:
            samples = first_lines(out)
            push( #добавляем найденные проблемы в список
                "предупреждение",
                "Права 666 (всем можно писать)",
                "Где: "
                + d
                + "\nПримеры:\n- "
                + "\n- ".join(samples),
                "снизить права (обычно chmod 644).",
                evidence=samples,
                category="fs",
            )

#sticky-bit и общие директории (важно для tmp) проверка
    for td in ("/tmp", "/var/tmp"):
        try:
            st = os.stat(td)
            mode = stat.S_IMODE(st.st_mode)
            sticky = bool(st.st_mode & stat.S_ISVTX)
            other_writable = bool(mode & 0o002)
            group_writable = bool(mode & 0o020)
            if (other_writable or group_writable) and not sticky:
                push(
                    "ошибка" if td == "/tmp" else "предупреждение",
                    f"Директория {td} доступна на запись без sticky-bit",
                    f"{td}: mode={oct(mode)} sticky={sticky}",
                    "включить sticky-bit: chmod +t " + td,
                    evidence=[f"mode={oct(mode)} sticky={sticky}"],
                    category="fs",
                )
        except Exception:
            pass

    ww_dirs = run(["find", "/tmp", "/var/tmp", "/var", "/opt", "/home", "-xdev", "-type", "d", "-perm", "-0002", "-print"], timeout=35)
    if ww_dirs:
        samples = first_lines(ww_dirs, n=8)
        push(
            "предупреждение",
            "Найдены директории с world-writable (others write)",
            "Примеры:\n- " + "\n- ".join(samples),
            "проверить, кому реально нужна запись; где можно — убрать права всем и/или включить sticky-bit.",
            evidence=samples,
            category="fs",
        )

#проверка cron hardening (world-writable cron файлы)
    cron_ww = run(["find", "/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.monthly", "/etc/cron.weekly", "-xdev", "-type", "f", "-perm", "-0002", "-print"], timeout=30)
    if cron_ww:
        samples = first_lines(cron_ww)
        push(
            "ошибка",
            "Найдены world-writable cron-скрипты",
            "Директории планировщика содержат файлы с опасными правами (others write):\n- " + "\n- ".join(samples),
            "ограничить права через chmod (обычно chmod 644 для скриптов, chmod 755 для исполняемых); проверить целостность скриптов (может быть компрометация).",
            evidence=samples,
            category="fs",
        )

#проверка setuid/setgid
    suid = run(["find", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "-xdev", "-type", "f", "-perm", "-4000", "-print"], timeout=60)
    sgid = run(["find", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "-xdev", "-type", "f", "-perm", "-2000", "-print"], timeout=60)
    if suid or sgid:
        samples = first_lines(suid if suid else "", n=10)
        samples2 = first_lines(sgid if sgid else "", n=10)
        push(
            "предупреждение",
            "В системе есть setuid/setgid файлы",
            "Примеры setuid:\n- " + "\n- ".join(samples) + "\nПримеры setgid:\n- " + "\n- ".join(samples2),
            "проверить, зачем нужны setuid/setgid; убрать лишние и оставить только нужные бинарники.",
            evidence=(samples + samples2)[:12],
            category="fs",
        )

#поиск секретиков
    kw = re.compile(
        r"(password|passwd|secret|token|api[_-]?key|private[_-]?key|access[_-]?key|key=|-----BEGIN\s+.*PRIVATE\s+KEY-----)",
        re.I,
    ) #регулярное выражение для поиска секретов (включая маркеры приватных ключей)
    for d in ("/etc", "/home"):
        files = run(["find", d, "-type", "f", "-perm", "-0004", "-size", "-200k", "-print"], timeout=30) #команда поиска файлов с правами 0004
        if not files:
            continue

        hits = [] #список найденных файлов
        for path in files.splitlines():
            if len(hits) >= 10: #если найдено 10 файлов
                break 
            try: #если файл не открывается
                with open(path, "r", encoding="utf-8", errors="ignore") as f: #открываем файл
                    chunk = f.read(4000) #читаем файл
            except Exception:
                continue
            if kw.search(chunk): #если в файле есть секрет
                hits.append(path) #добавляем файл в список

        if hits:
            samples = hits[:5]
            push( #добавляем найденные проблемы в список
                "предупреждение",
                "Похоже на секреты в доступных всем файлах",
                "Где: " + d + "\nПримеры:\n- " + "\n- ".join(samples),
                "проверить содержимое, убрать секреты, снизить права (команда chmod 600/640).",
                evidence=samples,
                category="fs",
            )

#сеть (порты + бд)
    ss = run(["ss", "-tulpn"]) #команда поиска портов
    if not ss:
        push(
            "предупреждение",
            "Не получилось прочитать порты (ss)",
            "Команда ss не дала вывода.",
            "проверь iproute2 и права доступа.",
            category="network",
        )
    else: #если получилось прочитать порты
        listen_lines = [x for x in ss.splitlines() if "LISTEN" in x]
        joined = "\n".join(listen_lines) #соединяем строки
        telnet_line = next((x for x in listen_lines if ":23" in x), None)
        if telnet_line:
            push(
                "ошибка",
                "Открыт Telnet (23)",
                "Найден LISTEN на порту 23.",
                "Отключить telnet и закрыть порт (ufw deny 23).",
                evidence=[telnet_line],
                category="network",
            )

        ftp_line = next((x for x in listen_lines if ":21" in x), None)
        if ftp_line:
            push(
                "предупреждение",
                "Открыт FTP (21)",
                "Найден LISTEN на порту 21.",
                "Если не нужен — отключить и закрыть порт (ufw deny 21).",
                evidence=[ftp_line],
                category="network",
            )

        smb_lines = [x for x in listen_lines if ":445" in x or ":139" in x]
        if smb_lines:
            push(
                "предупреждение",
                "Открыт SMB (139/445)",
                "Найдены LISTEN на SMB-портах.",
                "Если не нужен — отключить samba и закрыть порты.",
                evidence=smb_lines[:3],
                category="network",
            )

        mysql_lines = [x for x in listen_lines if ":3306" in x]
        not_local = [x for x in mysql_lines if "127.0.0.1:3306" not in x and "[::1]:3306" not in x]
        if not_local:
            push(
                "предупреждение",
                "MySQL доступен не только локально",
                "Порт 3306 слушает не только localhost.",
                "Ограничить bind-address=127.0.0.1 или firewall.",
                evidence=not_local[:3],
                category="network",
            )

#пакеты и версии (dpkg)
    pkgs = run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\n"]) #команда поиска пакетов
    if not pkgs: #если не получилось получить список пакетов
        push( #добавляем найденные проблемы в список
            "предупреждение",
            "Не получилось получить список пакетов",
            "dpkg-query не дал вывода.",
            "проверь, что это Debian/Kali/Ubuntu и доступен dpkg.",
            category="network",
        )
    else: #если получилось получить список пакетов
        interesting = { #популярные пакеты
            "openssh-server",
            "apache2",
            "nginx",
            "mysql-server",
            "mariadb-server",
            "vsftpd",
            "telnetd",
            "samba",
        }
        found = [] #список найденных пакетов
        for line in pkgs.splitlines(): #делим строку на части
            pkg = line.split("\t", 1)[0]
            if pkg in interesting: #если пакет в списке популярных
                found.append(line)

        if found: #если найдены популярные пакеты
            push(
                "предупреждение",
                "Установлены популярные сетевые пакеты",
                "Нашлось:\n- " + "\n- ".join(found),
                "проверь актуальность версий и отключи ненужные сервисы.",
                evidence=found[:10],
                category="network",
            )

    kernel = run(["uname", "-r"]) #команда поиска версии ядра
    if kernel: #если получилось прочитать версию ядра
        push(
            "предупреждение",
            "Версия ядра",
            kernel,
            "если ядро старое — обновить пакеты/ядро (apt update && apt upgrade).",
            evidence=[kernel],
            category="admin",
        )

#SSH конфиг (sshd_config) и sudoers
    ssh_files = ["/etc/ssh/sshd_config"] + glob.glob("/etc/ssh/sshd_config.d/*.conf") #список файлов ssh_config
    ssh_hits = [] #список найденных рискованных настроек
    ssh_patterns = { #шаблоны для поиска рискованных настроек
        "PermitRootLogin": re.compile(r"^\s*PermitRootLogin\s+(yes|without-password)\b", re.I),
        "PasswordAuthentication": re.compile(r"^\s*PasswordAuthentication\s+yes\b", re.I),
        "PermitEmptyPasswords": re.compile(r"^\s*PermitEmptyPasswords\s+yes\b", re.I),
    }
    for cfg in ssh_files: #перебираем файлы ssh_config
        if not os.path.exists(cfg):
            continue
        try:
            with open(cfg, "r", encoding="utf-8", errors="ignore") as f: #открываем файл
                for line in f: #читаем файл построчно
                    raw = line.rstrip("\n")
                    no_comment = raw.split("#", 1)[0].strip() #убираем комментарии
                    if not no_comment:
                        continue
                    for key, rx in ssh_patterns.items(): #перебираем шаблоны
                        if rx.search(no_comment):
                            ssh_hits.append(f"{cfg}: {raw.strip()}") #добавляем найденную рискованную настройку в список
        except Exception:
            continue

    if ssh_hits: #если найдены рискованные настройки
        severity = "ошибка" if any("PermitEmptyPasswords" in h for h in ssh_hits) else "предупреждение" 
        push( #добавляем найденные проблемы в список
            severity,
            "Рискованные настройки SSH (проверь sshd_config)",
            "Найдено:\n- " + "\n- ".join(ssh_hits[:6]),
            "привести параметры к безопасным значениям (например запретить root по паролю/empty passwords, ограничить PasswordAuthentication).",
            evidence=ssh_hits[:6],
            category="admin",
        )

    sudo_hits = [] #список найденных рискованных настроек sudoers
    nopass_rx = re.compile(r"\bNOPASSWD\s*:\s*", re.I) #шаблон для поиска рискованных настроек sudoers
    sudo_files = ["/etc/sudoers"] + glob.glob("/etc/sudoers.d/*") #список файлов sudoers
    for p in sudo_files:
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8", errors="ignore") as f: #открываем файл
                for line in f:
                    raw = line.rstrip("\n")
                    no_comment = raw.split("#", 1)[0].strip() #убираем комментарии
                    if nopass_rx.search(no_comment): #если в строке есть рискованная настройка
                        sudo_hits.append(f"{p}: {raw.strip()}")
        except Exception:
            continue

    if sudo_hits: #если найдены рискованные настройки sudoers
        push( #добавляем найденные проблемы в список
            "ошибка",
            "В sudoers найден NOPASSWD",
            "Найдено:\n- " + "\n- ".join(sudo_hits[:6]),
            "убрать NOPASSWD (или ограничить пользователей/команды), чтобы не было админ-доступа без пароля.",
            evidence=sudo_hits[:6],
            category="admin",
        )

#фильтрация результатов под выбранный тип проверки (по категориям).
    findings = [f for f in findings if f.get("category") in allowed_categories]

#вывод и джсон
    findings.sort(key=lambda x: {"ошибка": 0, "предупреждение": 1}.get(x["тип"], 9))
    print("Найдено:", len(findings))
    for i, f in enumerate(findings, 1): #выводим найденные проблемы
        print(f"\n{i}) [{f['тип']}] {f['проблема']}")
        if f.get("детали"): #если есть детали
            for line in str(f["детали"]).splitlines(): #делим строку на части
                print("   ", line)
        print("   Что делать:", f["рекомендация"]) #выводим рекомендации

    with open("report.json", "w", encoding="utf-8") as fp: #сохраняем отчет в джсон
        json.dump({"время": t, "всего": len(findings), "пункты": findings}, fp, indent=2, ensure_ascii=False)
    print("\nОтчет сохранен в report.json") #выводим сообщение о сохранении отчета


def _run_cmd(args, timeout=15): #функция для выполнения команд
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout) #выполняем команду
        out = (r.stdout or "").strip() #получаем вывод
        err = (r.stderr or "").strip() #получаем ошибки
        return out or err or "" #возвращаем результат
    except Exception: #если произошла ошибка
        return ""


def get_linux_version_text(): #функция для получения версии линукса и ядра
    osrel = {}
    try:
        with open("/etc/os-release", "r", encoding="utf-8", errors="ignore") as f: #открываем файл
            for line in f:
                line = line.strip()
                if not line or "=" not in line: #если строка пустая или не содержит =
                    continue
                k, v = line.split("=", 1) #делим строку на части
                v = v.strip().strip('"') #убираем кавычки
                osrel[k] = v #добавляем в словарь
    except Exception: #если произошла ошибка
        pass

    pretty = osrel.get("PRETTY_NAME")
    name = osrel.get("NAME", "Linux") #получаем имя системы
    version = osrel.get("VERSION", "") #получаем версию системы
    kernel = _run_cmd(["uname", "-r"], timeout=10)

    if pretty: #если есть pretty_name
        return f"{pretty}\nKernel: {kernel}".strip()
    if version: #если есть версия
        return f"{name} {version}\nKernel: {kernel}".strip()
    return f"{name}\nKernel: {kernel}".strip()

#меню
def show_menu():
    print("1. По сетям (порты + сетевые пакеты)")
    print("2. По файловой системе (права + секретики)")
    print("3. Админ-доступ (SSH + sudoers + ядро)")
    print("4. Полная проверка")
    print("5. Версия Linux")
    print("0. Выход")
    choice = input("Выбор: ").strip()
    return choice

#взаимодействие с меню (логика меню)
def main_entry():
    parser = argparse.ArgumentParser(description="Автоаудит Linux (офлайн, без интернета).")
    parser.add_argument("--check", action="store_true", help="Запустить проверку сразу (и сохранить report.json).")
    parser.add_argument("--version", action="store_true", help="Показать версию Linux и ядра.")
    parser.add_argument("--menu", action="store_true", help="Показать меню (если интерактивно).")
    args = parser.parse_args()

    if args.version: #если нужно показать версию линукса и ядра
        print(get_linux_version_text()) 
        return

    is_interactive = sys.stdin.isatty() #проверяем, является ли ввод интерактивным
    if args.menu or (is_interactive and not args.check): #если нужно показать меню или интерактивно и не нужно запускать проверку
        while True: #
            choice = show_menu()
            if choice == "5":
                print(get_linux_version_text())
                continue
            if choice in ("0", "q", "й", "йо"):
                return
            # Enter/пустой ввод считаем полной проверкой.
            if choice == "":
                main("full")
                continue

            mode_map = {
                "1": "network",
                "2": "fs",
                "3": "admin",
                "4": "full",
            }
            main(mode_map.get(choice, "full"))
            continue

#если запуск не интерактивный — сразу проверка
    main("full")


if __name__ == "__main__":
    main_entry()
