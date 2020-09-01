FROM squidfunk/mkdocs-material:5.5.12

RUN \
  apk add --no-cache \
    git \
    git-fast-import \
    openssh \
  && apk add --no-cache --virtual .build gcc musl-dev \
  && pip install --no-cache-dir \
    'markdown-include' \
    'mike' \
    'mkdocs-exclude' \
    'mkdocs-macros-plugin' \
  && apk del .build gcc musl-dev \
  && rm -rf /tmp/*
