# Обновления Vezde VPN для macOS

Vezde проверяет `vezde-update.json` в этой папке в ветке `codex/vox-integration`. В манифесте указаны версия, ссылка на ZIP в GitHub Releases и SHA-256 архива. Выпуски Vezde используют теги `vezde-vX.Y.Z`.

1. Обновите версию и номер сборки в `VezdeVPN/version`.
2. Соберите архив и манифест командой `VezdeVPN/package-update.sh`. Она проверит архив штатным установщиком обновлений.
3. Отправьте исходный коммит в `codex/vox-integration`. Опубликуйте ZIP и манифест в GitHub Release с тегом версии, направленным на этот коммит. Для демо-выпусков используйте `--prerelease --latest=false`.
4. Скачайте ZIP из опубликованного выпуска и сверьте SHA-256. Затем положите новый `vezde-update.json` в эту папку и отправьте коммит.
