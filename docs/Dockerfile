FROM squidfunk/mkdocs-material:7.2.4

RUN apk add --no-cache \
    git \
    git-fast-import \
    openssh \
  && apk add --no-cache --virtual .build gcc musl-dev \
  && pip install --no-cache-dir \
    'lunr' \
    'markdown-include' \
    'mkdocs-awesome-pages-plugin' \
    'mkdocs-exclude' \
    'mkdocs-git-revision-date-localized-plugin' \
    'mkdocs-macros-plugin' \
  && apk del .build gcc musl-dev \
  && rm -rf /tmp/*
