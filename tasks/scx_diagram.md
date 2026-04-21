# Замена картинки на слайде 7 «sched\_ext»

## Проблема

Текущая картинка `events/0212/res/libbpf.png` подписана
«eBPF в сетевой подсистеме». Слайд про планировщик — картинка не
релевантна теме.

Временно подпись изменена на нейтральную («eBPF как общая
инфраструктура»), но это не решает проблему — визуал всё равно про
сетевой стек.

## Что нужно

Схема sched\_ext с элементами:

- DSQ (local / global / user-defined)
- Цикл планирования: `select_cpu` → `enqueue` → `dispatch` →
  `running` / `stopping`
- eBPF-программа как user-space расширение, подключаемое к хукам
- Граница kernel / user (BPF struct\_ops)

## Варианты

1. **Нарисовать самому** в TikZ. Преимущество: векторное, под стиль
   презентации. ~1–2 часа.

2. **Взять из arXiv:2408.01997** (Agrawal et al., sched\_ext paper) —
   в статье есть архитектурная схема. Требуется проверить лицензию /
   указать источник.

3. **LWN article** https://lwn.net/Articles/922405 — там может быть
   схема. Указать ссылку как источник.

4. **Schema из scx репозитория** — github.com/sched-ext/scx. Возможно
   есть в docs/.

## Рекомендация

Вариант 1 (TikZ). Даёт контроль над стилем, интегрируется с темой
beamer. Шаблон:

```latex
\begin{tikzpicture}[node distance=1.2cm]
  \node[draw, rounded corners] (task) {Задача};
  \node[draw, rounded corners, right=of task] (enq) {enqueue};
  \node[draw, rounded corners, right=of enq] (dsq) {DSQ\_P / DSQ\_E};
  \node[draw, rounded corners, right=of dsq] (disp) {dispatch};
  \node[draw, rounded corners, right=of disp] (cpu) {CPU};
  \draw[->] (task) -- (enq);
  \draw[->] (enq) -- (dsq);
  \draw[->] (dsq) -- (disp);
  \draw[->] (disp) -- (cpu);
\end{tikzpicture}
```

## Статус

Открыто. TODO-комментарий в `events/2104/main.tex` на месте
`\includegraphics{libbpf.png}`.
