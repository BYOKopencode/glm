# syntax=docker/dockerfile:1

# Playwright's official Python image ships Chromium plus every system library a
# real browser needs (libnss3, libatk, libxkbcommon, fonts, ...).
# Do NOT switch to python:slim -- Chromium will fail with missing .so files.
#
# Keep PLAYWRIGHT_VERSION in sync with the playwright pin in requirements.txt.
ARG PLAYWRIGHT_VERSION=1.48.0
FROM mcr.microsoft.com/playwright/python:v${PLAYWRIGHT_VERSION}-jammy

# ARGs declared before FROM are out of scope afterwards; redeclare to use it.
ARG PLAYWRIGHT_VERSION

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

WORKDIR /app

# Dependencies first so edits to main.py do not invalidate the pip layer.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Chromium is preinstalled in the base image. Running install again guarantees
# the browser build matches the pip package resolved above, which is the exact
# failure behind "Executable doesn't exist at .../chrome-headless-shell".
RUN python -m playwright install chromium

# Copy the app and fail the BUILD, not the first request, if the file was
# corrupted in transit (zero-width characters, markdown mangling) or does not
# parse. --selfcheck needs no third-party imports.
COPY main.py .
RUN python -m py_compile main.py \
 && python main.py --selfcheck \
 && rm -rf __pycache__

COPY . .

# Railway injects $PORT. Default 8000 for plain `docker run`.
ENV PORT=8000
EXPOSE 8000

# /health does not touch the browser, so it stays green during a cold start.
# start-period is generous: the first Chromium launch is slow.
HEALTHCHECK --interval=30s --timeout=5s --start-period=90s --retries=3 \
  CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/health', timeout=4)" || exit 1

# Launch via python so PORT is read inside main.py. Avoids shell/exec-form
# ${PORT} expansion problems on Railway.
CMD ["python", "main.py"]
