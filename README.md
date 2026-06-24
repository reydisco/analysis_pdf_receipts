# PDF Receipt Analyzer

Python-сервис для анализа PDF-чеков и выявления признаков подделки. Каждый файл анализируется **независимо**; допускается сравнение с эталонными профилями банков.

## Запуск

### Docker (рекомендуется)

```bash
docker compose up --build
```

Сервис будет доступен на `http://localhost:8000`.

### Локально

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API

### POST `/check-receipt/`

Принимает один или несколько PDF-файлов (`multipart/form-data`, поле `files`), запускает анализ и сохраняет отчёт в `reports/{analysis_id}.json`.

```bash
curl -X POST "http://localhost:8000/check-receipt/" \
  -F "files=@receipt_1.pdf" \
  -F "files=@receipt_2.pdf"
```

Пример ответа:

```json
{
  "analysis_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "files": ["receipt_1.pdf", "receipt_2.pdf"]
}
```

### GET `/receipt/{analysis_id}`

Возвращает сохранённый отчёт анализа.

```bash
curl "http://localhost:8000/receipt/550e8400-e29b-41d4-a716-446655440000"
```

### GET `/health`

Проверка доступности сервиса.

## Возможные результаты по файлу

| Вердикт | Описание |
|---------|----------|
| `original` | Значимых признаков подделки не обнаружено |
| `suspicious` | Есть отдельные аномалии |
| `fake` | Много или сильных признаков подделки |
| `unknown` | PDF не удалось проанализировать |

## Реализованные проверки

| Проверка | Вес | Что анализирует |
|----------|-----|-----------------|
| `metadata_producer` | 0.15 | Producer/Creator (Print to PDF, Word, Photoshop, Canva и т.п.) |
| `metadata_date_consistency` | 0.10 | CreationDate vs ModDate (в т.ч. ModDate сильно позже) |
| `structure_pdf_version` | 0.05 | Версия PDF vs типичная для банковских чеков |
| `structure_pdf_integrity` | 0.15 | %PDF, xref, trailer, %%EOF, число ревизий, obj count |
| `structure_file_fingerprint` | 0.12 | MD5 файла vs blacklist известных подделок |
| `structure_generator` | 0.15 | Blacklist content/font-потоков известного фейкового генератора |
| `structure_batch_clone` | 0.10 | Дубликаты и структурные клоны в одном запросе |
| `structure_image_only` | 0.15 | PDF только как изображение; OCR fallback при отсутствии текста |
| `structure_security` | 0.10 | JavaScript, формы, вложения, шифрование |
| `structure_fonts` | 0.10 | Количество, типы и нетипичные шрифты vs эталон |
| `structure_images` | 0.15 | Наличие изображений, DPI (эталонные хеши — опционально в профиле) |
| `structure_layout` | 0.20 | Skeleton и Tm-сетка (опционально в профиле) |
| `structure_date_tm` | 0.12 | Tm строки даты vs эталон (опционально в профиле) |
| `content_required_fields` | 0.20 | Сумма, дата, статус/тип операции |
| `content_status` | 0.05 | Ключевые слова успешной операции |
| `content_inn` | 0.08 | ИНН и проверка контрольной суммы |
| `content_merchant` | 0.08 | Банк/организация/получатель в тексте |
| `reference_profile` | 0.15 | Producer vs эталонный профиль банка |

QR-код и цифровая подпись не проверяются. Наличие `/Sig` по-прежнему отражается в `technical_signs.has_digital_signature` (информационно).

В отчёте также возвращаются: `md5`, `sha256`, `stream_hashes`, `stream_details`, `generator_fingerprint`, `image_hashes`, `content_skeleton_md5`, `meta_text_delta_sec`, `ocr_used`, `font_types`, `max_image_dpi`, `inn_found`, `merchant_name`.

Критичные проверки (`metadata_producer`, `structure_layout`, `structure_date_tm`, `structure_images`, `structure_file_fingerprint`, `structure_generator`) при провале поднимают risk score минимум до порога `suspicious`.

## Профиль Сбербанка (упрощённый)

Для тестового задания в `reference_receipts/profiles.json` заданы только blacklist-поля:

| Поле | Назначение |
|------|------------|
| `known_sample_file_md5` | MD5 подтверждённых оригиналов (информационно) |
| `forbidden_file_md5` | MD5 известной подделки (`receipt_2`) |
| `fake_generator_stream_hashes` | content/font/cmap-потоки фейкового генератора (`receipt_2`) |

Опциональные поля (`expected_content_skeleton_md5`, `skeleton_image_fingerprints`, `expected_date_tm_by_skeleton` и т.п.) в профиле не заданы — соответствующие проверки пропускаются.

## Бланк vs генератор PDF

**Подделка** определяется по blacklist: MD5 файла или content/font-потоки совпадают с известным фейковым генератором (`fake_generator_stream_hashes`). Другая сумма или ФИО у легитимного чека дают другие stream-хеши — это нормально.

## Как формируется итоговый вывод

1. Из PDF извлекаются метаданные, текст, шрифты и структурные признаки.
2. По ключевым словам определяется банк (если возможно).
3. Запускается набор независимых проверок; каждая возвращает `passed`, `weight` и `details`.
4. Считается **risk score** — доля веса проваленных проверок от общего веса:

```
risk_score = sum(weight failed) / sum(weight all)
```

5. Вердикт:
   - `risk_score >= 0.7` → `fake`
   - `risk_score >= 0.35` → `suspicious`
   - иначе → `original`

6. В ответе указываются причины (детали проваленных проверок), технические и содержательные признаки PDF.

## Структура проекта

```
analysis_pdf_receipts/
├── app/                          # код сервиса
│   ├── main.py                   # точка входа FastAPI
│   ├── config.py                 # глобальные пороги и пути
│   ├── api/routes.py             # HTTP-эндпоинты
│   ├── models/schemas.py         # Pydantic-модели (вердикт, отчёт, признаки)
│   ├── services/
│   │   ├── analyzer.py           # оркестратор: extract → checks → verdict
│   │   ├── pdf_extractor.py      # извлечение текста, метаданных, шрифтов
│   │   ├── layer_extractor.py    # skeleton, Tm-позиции, хеши файла
│   │   ├── stream_analyzer.py    # MD5 потоков PDF (content/font/image)
│   │   ├── ocr_extractor.py      # OCR для image-only PDF
│   │   ├── verdict.py            # расчёт original/suspicious/fake
│   │   ├── checks/__init__.py    # все проверки + build_checks()
│   │   ├── reference_fingerprints.py
│   │   └── inn_utils.py
│   └── storage/report_store.py   # сохранение отчётов в reports/
├── reference_receipts/
│   └── profiles.json             # эталоны банков (главные настройки)
├── tests/
│   ├── test_checks.py            # unit-тесты проверок + receipt_1/2
│   └── test_verdict.py           # логика вердикта
├── reports/                      # JSON-отчёты после анализа
├── requirements.txt
├── Dockerfile / docker-compose.yml
└── README.md
```

## Тесты

```bash
pytest -q
```

## Swagger

После запуска документация доступна по адресу `http://localhost:8000/docs`.
