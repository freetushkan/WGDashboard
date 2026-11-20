#!/usr/bin/env python3
"""
awg31_patch.py — добавляет недостающие параметры AmneziaWG 3.1 в WGDashboard.

Кладётся в корень репозитория (/opt/WGDashboard, рядом с src/) и запускается
после каждого `./wgd.sh update`. Повторный запуск ничего не меняет.

Что правит (только там, где уже перечислены AWG-параметры — якорь I5):
  * .py   — self.I5 = ...            -> self.<New> = ""
            "I5": <expr>.I5,         -> "<New>": <expr>.<New>,
            [..., "I5", ...]         -> [..., "I5", "<New>", ...]
  * .vue/.js/.ts исходники фронтенда:
            I5: "",                  -> <New>: "",
            ['Jc', ..., 'I5']        -> ['Jc', ..., 'I5', '<New>', ...]
  * src/static/dist/**/*.js (уже собранный фронтенд, минифицированный):
            ["Jc",...,"I5"] и {...,Jc:..,I5:"0"} — так что пересобирать
            фронтенд не обязательно.

Новые ключи вставляются сразу после I5 (до J1/J2/J3/Itime), в порядке AWG_31.
Пустое значение по умолчанию ("") означает «не задано»: WGDashboard такие
ключи не пишет ни в серверный, ни в клиентский конфиг.

Использование:
  python3 awg31_patch.py              # пропатчить
  python3 awg31_patch.py --dry-run    # показать diff, ничего не менять
  python3 awg31_patch.py --check      # код 1, если есть что патчить (для cron/CI)
  python3 awg31_patch.py --restart    # пропатчить и сделать ./wgd.sh restart
"""
import argparse
import difflib
import os
import re
import subprocess
import sys

# Полный список ключей [Interface] AmneziaWG 3.1 (amneziawg-tools src/config.c).
AWG_31 = [
    "Jc", "Jmin", "Jmax",
    "S1", "S2", "S3", "S4",
    "H1", "H2", "H3", "H4",
    "I1", "I2", "I3", "I4", "I5",
    "HeaderProtectionKey", "ContentPaddingAddition",
    "RekeyAfterTime", "RekeyTimeout", "RejectAfterTime", "KeepaliveTimeout",
    "MaxHandshakeAttempts", "RandomTrailers", "DisableCookies",
]
ANCHOR = "I5"
NEW_KEYS = AWG_31[AWG_31.index(ANCHOR) + 1:]

SCAN_EXT = {".py", ".js", ".mjs", ".ts", ".vue"}
SKIP_DIRS = {"venv", "venv_bak", ".venv", "node_modules", "__pycache__", ".git",
             "log", "db", "download", "attachments"}


def missing(present):
    return [k for k in NEW_KEYS if k not in present]


# ---------------------------------------------------------------- построчные блоки
# Каждый вид: (регэксп строки-якоря, регэксп «соседней строки того же блока»
#              с группой имени ключа, функция генерации новой строки).

def _gen_attr(m, key):              # self.I5 = ""
    return f'{m.group("ind")}self.{key} = ""'


def _gen_dict(m, key):              # "I5": self.configuration.I5,
    rest = re.sub(r"\bI5\b", key, m.group("rest"))
    q = m.group("q")
    return f'{m.group("ind")}{q}{key}{q}{m.group("sep")}{rest}'


def _gen_jsobj(m, key):             # I5: "",
    q = '"' if '"' in m.group("rest") or "'" not in m.group("rest") else "'"
    return f'{m.group("ind")}{key}{m.group("sep")}{q}{q}'


LINE_KINDS = [
    # Python: атрибуты в __init__
    (re.compile(r'^(?P<ind>[ \t]*)self\.I5\s*=\s*(?P<rest>.*?)(?P<comma>)\s*$'),
     re.compile(r'^[ \t]*self\.(\w+)\s*='),
     _gen_attr, {".py"}),
    # Python/JS: строки словаря "I5": <что-то с I5>
    (re.compile(r'^(?P<ind>[ \t]*)(?P<q>["\'])I5(?P=q)(?P<sep>\s*:\s*)'
                r'(?P<rest>.*?\bI5\b.*?)(?P<comma>,?)\s*$'),
     re.compile(r'^[ \t]*["\'](\w+)["\']\s*:'),
     _gen_dict, SCAN_EXT),
    # JS/Vue: литерал объекта I5: "" (значения по умолчанию новой конфигурации)
    (re.compile(r'^(?P<ind>[ \t]*)I5(?P<sep>\s*:\s*)(?P<rest>["\'][^"\']*["\'])'
                r'(?P<comma>,?)\s*$'),
     re.compile(r'^[ \t]*(\w+)\s*:'),
     _gen_jsobj, {".js", ".mjs", ".ts", ".vue"}),
]


def _block_keys(lines, i, member_re):
    keys = set()
    for rng in (range(i, -1, -1), range(i + 1, len(lines))):
        for j in rng:
            mm = member_re.match(lines[j])
            if not mm:
                break
            keys.add(mm.group(1))
    return keys


def patch_lines(text, ext):
    lines = text.split("\n")
    out, hits = [], []
    for i, line in enumerate(lines):
        new = None
        for anchor_re, member_re, gen, exts in LINE_KINDS:
            if ext not in exts:
                continue
            m = anchor_re.match(line)
            if not m:
                continue
            block = _block_keys(lines, i, member_re)
            if "Jc" not in block:            # не AWG-блок — не трогаем
                break
            add = missing(block)
            if not add:
                break
            new = [gen(m, k) for k in add]
            if gen is not _gen_attr:         # элементы словаря/объекта — через запятую
                if m.group("comma"):
                    new = [n + "," for n in new]
                else:                        # I5 был последним элементом
                    line = line.rstrip() + ","
                    new = [n + "," for n in new[:-1]] + new[-1:]
            hits.append((i + 1, add))
            break
        out.append(line)
        if new:
            out.extend(new)
    return "\n".join(out), hits


# ---------------------------------------------------------------- inline-списки
LIST_RE = re.compile(r'\[([^\[\]]*?(["\'])I5\2[^\[\]]*?)\]')


def patch_lists(text):
    hits = []

    def repl(m):
        body, q = m.group(1), m.group(2)
        items = re.findall(r'["\'](\w+)["\']', body)
        if "Jc" not in items:                # например ['I1',...,'I5'].forEach — не AWG-список целиком
            return m.group(0)
        add = missing(items)
        if not add:
            return m.group(0)
        sep = ", " if re.search(r",\s", body) else ","
        tok = f"{q}I5{q}"
        ins = "".join(f"{sep}{q}{k}{q}" for k in add)
        hits.append((text.count("\n", 0, m.start()) + 1, add))
        return "[" + body.replace(tok, tok + ins, 1) + "]"

    return LIST_RE.sub(repl, text), hits


# ---------------------------------------------------------------- собранный dist
MIN_OBJ_RE = re.compile(r'\bI5:(?P<v>"[^"]*"|\'[^\']*\'|`[^`]*`|[\w.]+)')


def patch_minified(text):
    hits = []
    pieces, last = [], 0
    for m in MIN_OBJ_RE.finditer(text):
        start = text.rfind("Jc:", max(0, m.start() - 3000), m.start())
        if start < 0:
            continue
        end = text.find("}", m.end())
        end = len(text) if end < 0 else end
        present = set(re.findall(r'(?:^|[{,\s])(\w+):', text[start - 1:end]))
        present.add("Jc")
        add = missing(present)
        if not add:
            continue
        pieces.append(text[last:m.end()])
        pieces.append("".join(f',{k}:""' for k in add))
        last = m.end()
        hits.append((text.count("\n", 0, m.start()) + 1, add))
    pieces.append(text[last:])
    return "".join(pieces), hits


# ---------------------------------------------------------------- обход файлов
def iter_files(src):
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in files:
            if os.path.splitext(f)[1] in SCAN_EXT:
                yield os.path.join(root, f)


def process(path, src):
    ext = os.path.splitext(path)[1]
    try:
        with open(path, encoding="utf-8") as fh:
            orig = fh.read()
    except (UnicodeDecodeError, OSError):
        return None
    if "I5" not in orig or "Jc" not in orig:
        return None
    is_dist = os.path.relpath(path, src).split(os.sep)[:2] == ["static", "dist"]
    text, hits = orig, []
    if not is_dist:
        text, h = patch_lines(text, ext)
        hits += h
    text, h = patch_lists(text)
    hits += h
    if is_dist:
        text, h = patch_minified(text)
        hits += h
    if text == orig:
        return None
    return orig, text, hits


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--dry-run", action="store_true", help="показать diff и выйти")
    ap.add_argument("--check", action="store_true", help="exit 1, если есть что патчить")
    ap.add_argument("--restart", action="store_true", help="после патча: ./wgd.sh restart")
    ap.add_argument("--src", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"),
                    help="путь к src/ (по умолчанию — src/ рядом со скриптом)")
    a = ap.parse_args()

    src = os.path.abspath(a.src)
    if not os.path.isfile(os.path.join(src, "dashboard.py")):
        sys.exit(f"Не похоже на WGDashboard/src: {src}")

    changed = 0
    for path in sorted(iter_files(src)):
        r = process(path, src)
        if not r:
            continue
        orig, new, hits = r
        changed += 1
        rel = os.path.relpath(path, os.path.dirname(src))
        for ln, add in hits:
            print(f"{rel}:{ln}: + {', '.join(add)}")
        if a.dry_run:
            if max(map(len, new.split("\n"))) < 2000:
                sys.stdout.writelines(difflib.unified_diff(
                    orig.splitlines(True), new.splitlines(True), f"a/{rel}", f"b/{rel}"))
            continue
        if a.check:
            continue
        st = os.stat(path)
        tmp = path + ".awg31.tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(new)
        os.chmod(tmp, st.st_mode)
        os.replace(tmp, path)

    if not changed:
        print("AWG 3.1: всё уже на месте, патчить нечего.")
        return 0
    if a.check:
        return 1
    if a.dry_run:
        print(f"\n(dry-run) файлов к изменению: {changed}")
        return 0

    # sanity: изменённые .py должны компилироваться
    bad = subprocess.run([sys.executable, "-m", "compileall", "-q",
                          os.path.join(src, "modules"), os.path.join(src, "dashboard.py")],
                         capture_output=True, text=True)
    if bad.returncode:
        print(bad.stdout, bad.stderr, file=sys.stderr)
        sys.exit("Ошибка компиляции после патча! Откатить: git -C %s checkout -- src" % os.path.dirname(src))

    print(f"\nПропатчено файлов: {changed}.")
    dist = os.path.join(src, "static", "dist")
    if not os.path.isdir(dist):
        print("dist/ не найден — пересобери фронтенд: (cd src/static/app && npm run build)")
    if a.restart:
        subprocess.run(["./wgd.sh", "restart"], cwd=src, check=False)
    else:
        print("Перезапусти: cd src && ./wgd.sh restart")
    return 0


if __name__ == "__main__":
    sys.exit(main())
