"""Схема протокола и графики результатов (по реальным замерам из tests/)."""
import json, re, sys
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle

BG, PANEL, TXT, MUT = '#0b1020', '#141d36', '#e6ebf7', '#8a96b3'
AMB, OK, BAD, BLUE = '#ffb83d', '#3ddc97', '#ff5d73', '#59a6ff'
plt.rcParams.update({'font.family': 'DejaVu Sans', 'text.color': TXT, 'axes.labelcolor': TXT,
                     'xtick.color': MUT, 'ytick.color': MUT, 'axes.edgecolor': '#24304f'})

def box(ax, x, y, w, h, title, lines, col=PANEL, edge='#24304f', tc=TXT):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle='round,pad=0.02,rounding_size=0.12', fc=col, ec=edge, lw=1.5))
    ax.text(x + w/2, y + h - 0.28, title, ha='center', va='top', fontsize=13, weight='bold', color=tc)
    for i, l in enumerate(lines):
        ax.text(x + w/2, y + h - 0.75 - i*0.36, l, ha='center', va='top', fontsize=9.5, color=MUT)

def arrow(ax, x1, y1, x2, y2, col=MUT, lw=1.6, style='-|>'):
    ax.add_patch(FancyArrowPatch((x1, y1), (x2, y2), arrowstyle=style, mutation_scale=14, color=col, lw=lw))

def protocol(path):
    fig = plt.figure(figsize=(16, 9), facecolor=BG)
    ax = fig.add_axes([0, 0, 1, 1]); ax.set_xlim(0, 16); ax.set_ylim(0, 9); ax.axis('off')
    ax.text(0.5, 8.55, 'МАЯК — мозаичный туннель', fontsize=24, weight='bold', color=TXT)
    ax.text(0.5, 8.1, 'Поток режется на «плитки»: каждое TLS-соединение несёт меньше порога «заморозки» ТСПУ и заменяется заранее открытым.', fontsize=11.5, color=MUT)

    box(ax, 0.4, 3.6, 2.6, 3.6, 'Приложения', ['браузер, Telegram,', 'v2rayN / NekoBox,', 'podkop (sing-box)', '', 'SOCKS5 / HTTP', '127.0.0.1:1080'])
    box(ax, 3.6, 3.6, 3.2, 3.6, 'Клиент МАЯК', ['мультиплексор потоков', 'нарезка по байтам', 'пул запасных TLS', 'отпечаток Chrome 156', '(uTLS, JA4 совпадает)', 'режим auto: проба 16 КБ'], edge=AMB)
    arrow(ax, 3.0, 5.4, 3.6, 5.4)

    # мозаика соединений
    x0, y0 = 7.3, 3.7
    ax.text(x0 + 1.75, 7.25, 'много коротких TLS 1.3', ha='center', fontsize=11, color=TXT, weight='bold')
    import random; random.seed(3)
    for r in range(6):
        for c in range(8):
            f = random.uniform(0.75, 0.84)
            ax.add_patch(Rectangle((x0 + c*0.44, y0 + r*0.52), 0.38, 0.44, fc='#1d2746', ec='none'))
            ax.add_patch(Rectangle((x0 + c*0.44, y0 + r*0.52), 0.38, 0.44*f, fc=BLUE, ec='none'))
    ax.text(x0 + 1.75, 3.35, 'каждая плитка ≤ 13,7 КБ  (порог 16 КБ)', ha='center', fontsize=9.5, color=MUT)
    arrow(ax, 6.8, 5.4, 7.25, 5.4)

    # ТСПУ
    ax.add_patch(FancyBboxPatch((10.95, 3.6), 0.9, 3.9, boxstyle='round,pad=0.02,rounding_size=0.1', fc='#2a1622', ec=BAD, lw=1.5))
    ax.text(11.4, 5.2, 'ТСПУ', rotation=90, ha='center', va='center', fontsize=14, weight='bold', color=BAD)
    arrow(ax, 10.85, 5.4, 12.45, 5.4, col=OK, lw=2.2)
    ax.text(11.4, 3.45, 'видит: HTTPS к сайту,\nChrome, мелкие соединения', ha='center', va='top', fontsize=9, color=MUT)

    box(ax, 12.5, 3.6, 3.1, 3.6, 'Сервер на VPS', ['обычный HTTPS (nginx-вид)', 'без ключа → сайт-заглушка', 'POST /up, GET /down', 'сборка по смещениям', 'повтор потерянного (RTO)', '→ выход в интернет'], edge=OK)

    # нижняя часть: сравнение
    ax.text(0.5, 2.55, 'Почему это работает', fontsize=13, weight='bold', color=TXT)
    ax.text(0.5, 2.1, 'Обычный VLESS/Trojan:  одно долгое TLS-соединение', fontsize=10.5, color=MUT)
    ax.add_patch(Rectangle((0.5, 1.55), 6.0, 0.35, fc='#1d2746'))
    ax.add_patch(Rectangle((0.5, 1.55), 0.6, 0.35, fc=BLUE)); ax.add_patch(Rectangle((1.1, 1.55), 5.4, 0.35, fc=BAD, alpha=.35))
    ax.text(1.2, 1.72, '16 КБ — дальше поток «замерзает»', va='center', fontsize=9.5, color=TXT)
    ax.text(0.5, 1.15, 'МАЯК:  тот же объём сотнями соединений', fontsize=10.5, color=MUT)
    for i in range(14):
        ax.add_patch(Rectangle((0.5 + i*0.43, 0.6), 0.39, 0.35, fc=BLUE))
    ax.text(6.7, 0.77, '…', va='center', fontsize=14, color=TXT)
    ax.text(7.6, 1.95, 'Надёжность: у каждого куска есть смещение в потоке (как в TCP), клиент подтверждает принятое (X-Ack).', fontsize=10, color=MUT)
    ax.text(7.6, 1.55, 'Оборвалось соединение — сервер повторит кусок, нарезав под текущий размер плитки.', fontsize=10, color=MUT)
    ax.text(7.6, 1.15, 'Крипто — только стандартное: TLS 1.3 (Go crypto/tls, uTLS) и HMAC-SHA256 токен в куки.', fontsize=10, color=MUT)
    ax.text(7.6, 0.75, 'Режим auto: если заморозки нет — длинные соединения (быстро), появилась — мозаика.', fontsize=10, color=MUT)
    fig.savefig(path, dpi=110, facecolor=BG); plt.close(fig)

def results(e2e, pcap_json, path):
    rows = []
    for line in open(e2e, encoding='utf-8'):
        m = re.match(r'(.+?)\s+(\d+\.\d) МБ за\s+([\d.]+) с =\s+([\d.]+) Мбит/с', line)
        if m: rows.append((m.group(1).strip(), float(m.group(4))))
    sim = [r for r in rows if 'RTT' in r[0]]
    fig, axs = plt.subplots(1, 2, figsize=(16, 6.2), facecolor=BG, gridspec_kw={'width_ratios': [1.15, 1]})
    for a in axs: a.set_facecolor(PANEL)
    ax = axs[0]
    labels = [r[0].replace('RTT 60 мс', 'RTT 60').replace(' + заморозка 16 КБ', ' + заморозка') for r in sim] + ['обычное одно\nTLS-соединение\n+ заморозка']
    vals = [r[1] for r in sim] + [0.0]
    cols = [OK if 'без' in l else AMB for l in labels[:-1]] + [BAD]
    y = range(len(vals))
    ax.barh(list(y), vals, color=cols)
    for i, v in enumerate(vals):
        ax.text(v + 1.5, i, ('%.1f Мбит/с' % v) if v else '≈ 8,6 КБ и тишина', va='center', fontsize=10.5, color=TXT)
    ax.set_yticks(list(y)); ax.set_yticklabels(labels, fontsize=10); ax.invert_yaxis()
    ax.set_xlim(0, max(vals) * 1.35); ax.set_xlabel('скорость скачивания 20 МБ, Мбит/с')
    ax.set_title('Через симулятор ТСПУ (RTT 60 мс, канал 100 Мбит/с)', color=TXT, fontsize=12.5, loc='left')
    ax = axs[1]
    d = json.load(open(pcap_json))['down_per_conn']
    d = [x for x in d if x > 0]
    ax.hist([x/1024 for x in d], bins=40, color=BLUE)
    ax.axvline(16, color=BAD, lw=2); ax.text(16.2, ax.get_ylim()[1]*0.9, 'порог\n16 КБ', color=BAD, fontsize=10)
    ax.set_xlim(0, 20); ax.set_xlabel('байт от сервера в одном TCP-соединении, КБ (дамп с провода)')
    ax.set_ylabel('соединений')
    ax.set_title('Дамп трафика: %d соединений, максимум %.1f КБ' % (len(d), max(d)/1024), color=TXT, fontsize=12.5, loc='left')
    fig.tight_layout(); fig.savefig(path, dpi=110, facecolor=BG); plt.close(fig)

if __name__ == '__main__':
    protocol('protocol.png')
    results(sys.argv[1], sys.argv[2], 'results.png')
    print('ok')
