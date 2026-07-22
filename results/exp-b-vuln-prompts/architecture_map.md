# WebGoat Architecture Map

Generated: 2026-07-22T08:43:24.555141+00:00
Revision: fd7ac42941ae54e3d50562fa94ef1aa8a9ee9d10
Branch: main
Java files scanned: 370 (excluded: 1)

## Maven Modules

- **webgoat** (`.`)

## Lesson Modules

| Module | Package | Files |
|--------|---------|-------|
| authbypass | `org.owasp.webgoat.lessons.authbypass` | 3 |
| bypassrestrictions | `org.owasp.webgoat.lessons.bypassrestrictions` | 3 |
| challenges | `org.owasp.webgoat.lessons.challenges` | 17 |
| chromedevtools | `org.owasp.webgoat.lessons.chromedevtools` | 3 |
| cia | `org.owasp.webgoat.lessons.cia` | 2 |
| clientsidefiltering | `org.owasp.webgoat.lessons.clientsidefiltering` | 5 |
| cryptography | `org.owasp.webgoat.lessons.cryptography` | 7 |
| csrf | `org.owasp.webgoat.lessons.csrf` | 7 |
| deserialization | `org.owasp.webgoat.lessons.deserialization` | 3 |
| hijacksession | `org.owasp.webgoat.lessons.hijacksession` | 5 |
| htmltampering | `org.owasp.webgoat.lessons.htmltampering` | 2 |
| httpbasics | `org.owasp.webgoat.lessons.httpbasics` | 3 |
| httpproxies | `org.owasp.webgoat.lessons.httpproxies` | 2 |
| idor | `org.owasp.webgoat.lessons.idor` | 8 |
| insecurelogin | `org.owasp.webgoat.lessons.insecurelogin` | 2 |
| jwt | `org.owasp.webgoat.lessons.jwt` | 10 |
| lessontemplate | `org.owasp.webgoat.lessons.lessontemplate` | 2 |
| logging | `org.owasp.webgoat.lessons.logging` | 3 |
| missingac | `org.owasp.webgoat.lessons.missingac` | 8 |
| passwordreset | `org.owasp.webgoat.lessons.passwordreset` | 9 |
| pathtraversal | `org.owasp.webgoat.lessons.pathtraversal` | 7 |
| securepasswords | `org.owasp.webgoat.lessons.securepasswords` | 2 |
| spoofcookie | `org.owasp.webgoat.lessons.spoofcookie` | 3 |
| sqlinjection | `org.owasp.webgoat.lessons.sqlinjection` | 23 |
| ssrf | `org.owasp.webgoat.lessons.ssrf` | 3 |
| vulnerablecomponents | `org.owasp.webgoat.lessons.vulnerablecomponents` | 4 |
| webgoatintroduction | `org.owasp.webgoat.lessons.webgoatintroduction` | 1 |
| webwolfintroduction | `org.owasp.webgoat.lessons.webwolfintroduction` | 4 |
| xss | `org.owasp.webgoat.lessons.xss` | 14 |
| xxe | `org.owasp.webgoat.lessons.xxe` | 9 |

## Spring Components

### Controllers (125)

- `HammerHead` — `src/main/java/org/owasp/webgoat/container/HammerHead.java:14`
- `WebWolfRedirect` — `src/main/java/org/owasp/webgoat/container/WebWolfRedirect.java:13`
- `StartLesson` — `src/main/java/org/owasp/webgoat/container/controller/StartLesson.java:13`
- `Welcome` — `src/main/java/org/owasp/webgoat/container/controller/Welcome.java:19`
- `ReportCardController` — `src/main/java/org/owasp/webgoat/container/report/ReportCardController.java:16`
- `LessonInfoService` — `src/main/java/org/owasp/webgoat/container/service/LessonInfoService.java:16`
- `RestartLessonService` — `src/main/java/org/owasp/webgoat/container/service/RestartLessonService.java:25`
- `LessonProgressService` — `src/main/java/org/owasp/webgoat/container/service/LessonProgressService.java:26`
- `HintService` — `src/main/java/org/owasp/webgoat/container/service/HintService.java:16`
- `LessonMenuService` — `src/main/java/org/owasp/webgoat/container/service/LessonMenuService.java:25`
- `EnvironmentService` — `src/main/java/org/owasp/webgoat/container/service/EnvironmentService.java:12`
- `SessionService` — `src/main/java/org/owasp/webgoat/container/service/SessionService.java:15`
- `LabelService` — `src/main/java/org/owasp/webgoat/container/service/LabelService.java:19`
- `LabelDebugService` — `src/main/java/org/owasp/webgoat/container/service/LabelDebugService.java:19`
- `RegistrationController` — `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java:27`
- `Scoreboard` — `src/main/java/org/owasp/webgoat/container/users/Scoreboard.java:24`
- `CIAQuiz` — `src/main/java/org/owasp/webgoat/lessons/cia/CIAQuiz.java:18`
- `SampleAttack` — `src/main/java/org/owasp/webgoat/lessons/lessontemplate/SampleAttack.java:24`
- `LandingAssignment` — `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/LandingAssignment.java:25`
- `MailAssignment` — `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/MailAssignment.java:27`
- `HttpBasicsLesson` — `src/main/java/org/owasp/webgoat/lessons/httpbasics/HttpBasicsLesson.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/httpbasics/HttpBasicsQuiz.java:18`
- `SpoofCookieAssignment` — `src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java:35`
- `SSRFTask2` — `src/main/java/org/owasp/webgoat/lessons/ssrf/SSRFTask2.java:23`
- `SSRFTask1` — `src/main/java/org/owasp/webgoat/lessons/ssrf/SSRFTask1.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/authbypass/VerifyAccount.java:26`
- `` — `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACHiddenMenus.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACYourHash.java:18`
- `MissingFunctionACUsers` — `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java:26`
- `` — `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACYourHashAdmin.java:18`
- `ResetLinkAssignmentForgotPassword` — `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignmentForgotPassword.java:31`
- `SecurityQuestionAssignment` — `src/main/java/org/owasp/webgoat/lessons/passwordreset/SecurityQuestionAssignment.java:26`
- `` — `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java:36`
- `SimpleMailAssignment` — `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java:30`
- `QuestionsAssignment` — `src/main/java/org/owasp/webgoat/lessons/passwordreset/QuestionsAssignment.java:24`
- `HttpBasicsInterceptRequest` — `src/main/java/org/owasp/webgoat/lessons/httpproxies/HttpBasicsInterceptRequest.java:21`
- `ShopEndpoint` — `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ShopEndpoint.java:22`
- `` — `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ClientSideFilteringAssignment.java:18`
- `Salaries` — `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/Salaries.java:32`
- `` — `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ClientSideFilteringFreeAssignment.java:22`
- `` — `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUpload.java:22`
- `` — `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java:40`
- `` — `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadFix.java:22`
- `` — `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRemoveUserInput.java:20`
- `` — `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java:37`
- `XOREncodingAssignment` — `src/main/java/org/owasp/webgoat/lessons/cryptography/XOREncodingAssignment.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/cryptography/SigningAssignment.java:27`
- `HashingAssignment` — `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java:25`
- `EncodingAssignment` — `src/main/java/org/owasp/webgoat/lessons/cryptography/EncodingAssignment.java:22`
- `` — `src/main/java/org/owasp/webgoat/lessons/cryptography/SecureDefaultsAssignment.java:19`
- `LogSpoofingTask` — `src/main/java/org/owasp/webgoat/lessons/logging/LogSpoofingTask.java:18`
- `LogBleedingTask` — `src/main/java/org/owasp/webgoat/lessons/logging/LogBleedingTask.java:23`
- `NetworkDummy` — `src/main/java/org/owasp/webgoat/lessons/chromedevtools/NetworkDummy.java:24`
- `NetworkLesson` — `src/main/java/org/owasp/webgoat/lessons/chromedevtools/NetworkLesson.java:26`
- `FlagController` — `src/main/java/org/owasp/webgoat/lessons/challenges/FlagController.java:18`
- `Assignment1` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/Assignment1.java:19`
- `ImageServlet` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/ImageServlet.java:18`
- `Assignment5` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java:24`
- `Assignment7` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java:36`
- `Assignment8` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Assignment8.java:23`
- `` — `src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java:20`
- `` — `src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfileAltUrl.java:19`
- `` — `src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java:19`
- `IDORLogin` — `src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java:21`
- `IDORViewOwnProfile` — `src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfile.java:15`
- `` — `src/main/java/org/owasp/webgoat/lessons/idor/IDORDiffAttributes.java:18`
- `HtmlTamperingTask` — `src/main/java/org/owasp/webgoat/lessons/htmltampering/HtmlTamperingTask.java:18`
- `VulnerableComponentsLesson` — `src/main/java/org/owasp/webgoat/lessons/vulnerablecomponents/VulnerableComponentsLesson.java:20`
- `SqlInjectionLesson6b` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java:23`
- `SqlInjectionQuiz` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionQuiz.java:24`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java:22`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java:25`
- `SqlInjectionChallengeLogin` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson9.java:25`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java:23`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5b.java:21`
- `SqlInjectionLesson4` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson4.java:25`
- `SqlInjectionLesson3` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java:25`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java:24`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java:23`
- `SqlInjectionLesson5a` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java:20`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java:24`
- `SqlInjectionLesson10a` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10a.java:19`
- `SqlOnlyInputValidation` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidation.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidationOnKeywords.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10b.java:31`
- `Servers` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/Servers.java:24`
- `` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson13.java:24`
- `BypassRestrictionsFieldRestrictions` — `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFieldRestrictions.java:17`
- `BypassRestrictionsFrontendValidation` — `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFrontendValidation.java:17`
- `CSRFFeedback` — `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFFeedback.java:29`
- `CSRFGetFlag` — `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFGetFlag.java:19`
- `CSRFLogin` — `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFLogin.java:18`
- `ForgedReviews` — `src/main/java/org/owasp/webgoat/lessons/csrf/ForgedReviews.java:30`
- `CSRFConfirmFlag1` — `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFConfirmFlag1.java:19`
- `InsecureLoginTask` — `src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLoginTask.java:15`
- `ContentTypeAssignment` — `src/main/java/org/owasp/webgoat/lessons/xxe/ContentTypeAssignment.java:30`
- `CommentsEndpoint` — `src/main/java/org/owasp/webgoat/lessons/xxe/CommentsEndpoint.java:21`
- `` — `src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java:26`
- `` — `src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java:33`
- `SecurePasswordsAssignment` — `src/main/java/org/owasp/webgoat/lessons/securepasswords/SecurePasswordsAssignment.java:22`
- `` — `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson5a.java:21`
- `` — `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson6a.java:19`
- `DOMCrossSiteScripting` — `src/main/java/org/owasp/webgoat/lessons/xss/DOMCrossSiteScripting.java:20`
- `CrossSiteScriptingQuiz` — `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingQuiz.java:19`
- `CrossSiteScriptingLesson1` — `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java:17`
- `` — `src/main/java/org/owasp/webgoat/lessons/xss/DOMCrossSiteScriptingVerifier.java:20`
- `StoredXssComments` — `src/main/java/org/owasp/webgoat/lessons/xss/stored/StoredXssComments.java:33`
- `StoredCrossSiteScriptingVerifier` — `src/main/java/org/owasp/webgoat/lessons/xss/stored/StoredCrossSiteScriptingVerifier.java:19`
- `CrossSiteScriptingLesson4` — `src/main/java/org/owasp/webgoat/lessons/xss/mitigation/CrossSiteScriptingLesson4.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/xss/mitigation/CrossSiteScriptingLesson3.java:20`
- `` — `src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java:30`
- `` — `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java:36`
- `JWTDecodeEndpoint` — `src/main/java/org/owasp/webgoat/lessons/jwt/JWTDecodeEndpoint.java:17`
- `JWTSecretKeyEndpoint` — `src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java:30`
- `` — `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java:45`
- `JWTQuiz` — `src/main/java/org/owasp/webgoat/lessons/jwt/JWTQuiz.java:18`
- `` — `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java:30`
- `` — `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java:31`
- `` — `src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java:24`
- `FileServer` — `src/main/java/org/owasp/webgoat/webwolf/FileServer.java:37`
- `MailboxController` — `src/main/java/org/owasp/webgoat/webwolf/mailbox/MailboxController.java:20`
- `JWTController` — `src/main/java/org/owasp/webgoat/webwolf/jwt/JWTController.java:17`
- `LandingPage` — `src/main/java/org/owasp/webgoat/webwolf/requests/LandingPage.java:15`
- `Requests` — `src/main/java/org/owasp/webgoat/webwolf/requests/Requests.java:28`

### Services (2)

- `UserService` — `src/main/java/org/owasp/webgoat/container/users/UserService.java:21`
- `UserService` — `src/main/java/org/owasp/webgoat/webwolf/user/UserService.java:15`

### Repositorys (1)

- `` — `src/main/java/org/owasp/webgoat/webwolf/user/UserRepository.java:14`

### Configurations (10)

- `ParentConfig` — `src/main/java/org/owasp/webgoat/server/ParentConfig.java:9`
- `WebSecurityConfig` — `src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java:23`
- `` — `src/main/java/org/owasp/webgoat/container/WebGoat.java:21`
- `DatabaseConfiguration` — `src/main/java/org/owasp/webgoat/container/DatabaseConfiguration.java:21`
- `MvcConfiguration` — `src/main/java/org/owasp/webgoat/container/MvcConfiguration.java:42`
- `CourseConfiguration` — `src/main/java/org/owasp/webgoat/container/lessons/CourseConfiguration.java:24`
- `Flags` — `src/main/java/org/owasp/webgoat/lessons/challenges/Flags.java:13`
- `` — `src/main/java/org/owasp/webgoat/webwolf/WebWolf.java:17`
- `WebSecurityConfig` — `src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java:24`
- `MvcConfiguration` — `src/main/java/org/owasp/webgoat/webwolf/MvcConfiguration.java:21`

### Components (45)

- `LessonResourceScanner` — `src/main/java/org/owasp/webgoat/container/LessonResourceScanner.java:17`
- `EnvironmentExposure` — `src/main/java/org/owasp/webgoat/container/asciidoc/EnvironmentExposure.java:17`
- `UserValidator` — `src/main/java/org/owasp/webgoat/container/users/UserValidator.java:16`
- `CIA` — `src/main/java/org/owasp/webgoat/lessons/cia/CIA.java:15`
- `LessonTemplate` — `src/main/java/org/owasp/webgoat/lessons/lessontemplate/LessonTemplate.java:11`
- `WebWolfIntroduction` — `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/WebWolfIntroduction.java:11`
- `HttpBasics` — `src/main/java/org/owasp/webgoat/lessons/httpbasics/HttpBasics.java:11`
- `SpoofCookie` — `src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookie.java:17`
- `SSRF` — `src/main/java/org/owasp/webgoat/lessons/ssrf/SSRF.java:12`
- `AuthBypass` — `src/main/java/org/owasp/webgoat/lessons/authbypass/AuthBypass.java:11`
- `MissingFunctionAC` — `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionAC.java:11`
- `MissingAccessControlUserRepository` — `src/main/java/org/owasp/webgoat/lessons/missingac/MissingAccessControlUserRepository.java:15`
- `TriedQuestions` — `src/main/java/org/owasp/webgoat/lessons/passwordreset/TriedQuestions.java:12`
- `PasswordReset` — `src/main/java/org/owasp/webgoat/lessons/passwordreset/PasswordReset.java:11`
- `HttpProxies` — `src/main/java/org/owasp/webgoat/lessons/httpproxies/HttpProxies.java:12`
- `ClientSideFiltering` — `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ClientSideFiltering.java:11`
- `WebGoatIntroduction` — `src/main/java/org/owasp/webgoat/lessons/webgoatintroduction/WebGoatIntroduction.java:12`
- `PathTraversal` — `src/main/java/org/owasp/webgoat/lessons/pathtraversal/PathTraversal.java:11`
- `Cryptography` — `src/main/java/org/owasp/webgoat/lessons/cryptography/Cryptography.java:11`
- `LogSpoofing` — `src/main/java/org/owasp/webgoat/lessons/logging/LogSpoofing.java:12`
- `ChromeDevTools` — `src/main/java/org/owasp/webgoat/lessons/chromedevtools/ChromeDevTools.java:15`
- `ChallengeIntro` — `src/main/java/org/owasp/webgoat/lessons/challenges/ChallengeIntro.java:15`
- `Challenge1` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/Challenge1.java:15`
- `Challenge5` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Challenge5.java:15`
- `Challenge7` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Challenge7.java:15`
- `Challenge8` — `src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Challenge8.java:15`
- `IDOR` — `src/main/java/org/owasp/webgoat/lessons/idor/IDOR.java:12`
- `HtmlTampering` — `src/main/java/org/owasp/webgoat/lessons/htmltampering/HtmlTampering.java:12`
- `VulnerableComponents` — `src/main/java/org/owasp/webgoat/lessons/vulnerablecomponents/VulnerableComponents.java:11`
- `SqlInjectionAdvanced` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionAdvanced.java:11`
- `SqlInjection` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjection.java:11`
- `SqlInjectionMitigations` — `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionMitigations.java:11`
- `BypassRestrictions` — `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictions.java:11`
- `CSRF` — `src/main/java/org/owasp/webgoat/lessons/csrf/CSRF.java:12`
- `InsecureLogin` — `src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLogin.java:12`
- `XXE` — `src/main/java/org/owasp/webgoat/lessons/xxe/XXE.java:11`
- `CommentsCache` — `src/main/java/org/owasp/webgoat/lessons/xxe/CommentsCache.java:23`
- `SecurePasswords` — `src/main/java/org/owasp/webgoat/lessons/securepasswords/SecurePasswords.java:15`
- `CrossSiteScripting` — `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScripting.java:11`
- `CrossSiteScriptingStored` — `src/main/java/org/owasp/webgoat/lessons/xss/stored/CrossSiteScriptingStored.java:11`
- `CrossSiteScriptingMitigation` — `src/main/java/org/owasp/webgoat/lessons/xss/mitigation/CrossSiteScriptingMitigation.java:11`
- `HijackSession` — `src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSession.java:17`
- `HijackSessionAuthenticationProvider` — `src/main/java/org/owasp/webgoat/lessons/hijacksession/cas/HijackSessionAuthenticationProvider.java:25`
- `JWT` — `src/main/java/org/owasp/webgoat/lessons/jwt/JWT.java:15`
- `InsecureDeserialization` — `src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserialization.java:12`

## REST Endpoints

Total: 189

| Method | Path | Java Method | File | Line |
|--------|------|-------------|------|------|
| ANY | `/attack` | `attack` | `src/main/java/org/owasp/webgoat/container/HammerHead.java` | 21 |
| GET | `/WebWolf` | `openWebWolf` | `src/main/java/org/owasp/webgoat/container/WebWolfRedirect.java` | 19 |
| GET | `/ has no mapping like @GetMapping/@PostMapping etc,with return type 'AttackResult' or` | `methodReturnTypeIsOfTypeAttackResult` | `src/main/java/org/owasp/webgoat/container/lessons/CourseConfiguration.java` | 122 |
| POST | `/ has no mapping like @GetMapping/@PostMapping etc,with return type 'AttackResult' or` | `methodReturnTypeIsOfTypeAttackResult` | `src/main/java/org/owasp/webgoat/container/lessons/CourseConfiguration.java` | 122 |
| GET | `/attack` | `` | `src/main/java/org/owasp/webgoat/container/lessons/CourseConfiguration.java` | 140 |
| GET | `/*.lesson` | `lessonPage` | `src/main/java/org/owasp/webgoat/container/controller/StartLesson.java` | 22 |
| GET | `/welcome.mvc` | `welcome` | `src/main/java/org/owasp/webgoat/container/controller/Welcome.java` | 30 |
| GET | `/service/reportcard.mvc` | `reportCard` | `src/main/java/org/owasp/webgoat/container/report/ReportCardController.java` | 34 |
| GET | `/service/lessoninfo.mvc/{lesson}` | `getLessonInfo` | `src/main/java/org/owasp/webgoat/container/service/LessonInfoService.java` | 22 |
| GET | `/service/restartlesson.mvc/{lesson}` | `restartLesson` | `src/main/java/org/owasp/webgoat/container/service/RestartLessonService.java` | 35 |
| GET | `/service/lessonoverview.mvc/{lesson}` | `lessonOverview` | `src/main/java/org/owasp/webgoat/container/service/LessonProgressService.java` | 39 |
| GET | `/application/json` | `getHints` | `src/main/java/org/owasp/webgoat/container/service/HintService.java` | 36 |
| ANY | `application/json/application/json` | `showLeftNav` | `src/main/java/org/owasp/webgoat/container/service/LessonMenuService.java` | 44 |
| GET | `/server-directory` | `homeDirectory` | `src/main/java/org/owasp/webgoat/container/service/EnvironmentService.java` | 18 |
| ANY | `/service/enable-security.mvc/service/enable-security.mvc` | `applySecurity` | `src/main/java/org/owasp/webgoat/container/service/SessionService.java` | 22 |
| GET | `/` | `fetchLabels` | `src/main/java/org/owasp/webgoat/container/service/LabelService.java` | 31 |
| ANY | `/` | `checkDebuggingStatus` | `src/main/java/org/owasp/webgoat/container/service/LabelDebugService.java` | 35 |
| ANY | `/` | `setDebuggingStatus` | `src/main/java/org/owasp/webgoat/container/service/LabelDebugService.java` | 48 |
| GET | `/registration` | `showForm` | `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java` | 35 |
| POST | `/register.mvc` | `registration` | `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java` | 40 |
| GET | `/login-oauth.mvc` | `registrationOAUTH` | `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java` | 65 |
| GET | `/scoreboard-data` | `getRankings` | `src/main/java/org/owasp/webgoat/container/users/Scoreboard.java` | 40 |
| POST | `/cia/quiz` | `completed` | `src/main/java/org/owasp/webgoat/lessons/cia/CIAQuiz.java` | 24 |
| GET | `/cia/quiz` | `getResults` | `src/main/java/org/owasp/webgoat/lessons/cia/CIAQuiz.java` | 55 |
| POST | `/lesson-template/sample-attack` | `completed` | `src/main/java/org/owasp/webgoat/lessons/lessontemplate/SampleAttack.java` | 35 |
| GET | `/lesson-template/shop/{user}` | `getItemsInBasket` | `src/main/java/org/owasp/webgoat/lessons/lessontemplate/SampleAttack.java` | 64 |
| POST | `/WebWolf/landing` | `click` | `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/LandingAssignment.java` | 33 |
| GET | `/WebWolf/landing/password-reset` | `openPasswordReset` | `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/LandingAssignment.java` | 42 |
| POST | `/WebWolf/mail/send` | `sendEmail` | `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/MailAssignment.java` | 39 |
| POST | `/WebWolf/mail` | `completed` | `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/MailAssignment.java` | 71 |
| POST | `/HttpBasics/attack1` | `completed` | `src/main/java/org/owasp/webgoat/lessons/httpbasics/HttpBasicsLesson.java` | 22 |
| POST | `/HttpBasics/attack2` | `completed` | `src/main/java/org/owasp/webgoat/lessons/httpbasics/HttpBasicsQuiz.java` | 26 |
| POST | `/SpoofCookie/login` | `login` | `src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java` | 46 |
| GET | `/SpoofCookie/cleanup` | `cleanup` | `src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java` | 62 |
| POST | `/SSRF/task2` | `completed` | `src/main/java/org/owasp/webgoat/lessons/ssrf/SSRFTask2.java` | 27 |
| POST | `/SSRF/task1` | `completed` | `src/main/java/org/owasp/webgoat/lessons/ssrf/SSRFTask1.java` | 22 |
| POST | `/auth-bypass/verify-account` | `completed` | `src/main/java/org/owasp/webgoat/lessons/authbypass/VerifyAccount.java` | 41 |
| POST | `/access-control/hidden-menu` | `completed` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACHiddenMenus.java` | 26 |
| POST | `/access-control/user-hash` | `simple` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACYourHash.java` | 34 |
| GET | `/access-control/users` | `listUsers` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java` | 33 |
| GET | `/access-control/users` | `usersService` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java` | 50 |
| GET | `/access-control/users-admin-fix` | `usersFixed` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java` | 61 |
| POST | `/access-control/users` | `addUser` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java` | 76 |
| DELETE | `/user/{username}` | `` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java` | 90 |
| POST | `/access-control/user-hash-fix` | `admin` | `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACYourHashAdmin.java` | 37 |
| POST | `/PasswordReset/ForgotPassword/create-password-reset-link` | `sendPasswordResetLink` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignmentForgotPassword.java` | 53 |
| POST | `/PasswordReset/SecurityQuestions` | `completed` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/SecurityQuestionAssignment.java` | 80 |
| POST | `/PasswordReset/reset/login` | `login` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java` | 69 |
| GET | `/PasswordReset/reset/reset-password/{link}` | `resetPassword` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java` | 84 |
| POST | `/PasswordReset/reset/change-password` | `changePassword` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignment.java` | 100 |
| POST | `/PasswordReset/simple-mail` | `login` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java` | 41 |
| POST | `/PasswordReset/simple-mail/reset` | `resetPassword` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java` | 59 |
| POST | `/PasswordReset/questions` | `passwordReset` | `src/main/java/org/owasp/webgoat/lessons/passwordreset/QuestionsAssignment.java` | 37 |
| ANY | `/HttpProxies/intercept-request` | `completed` | `src/main/java/org/owasp/webgoat/lessons/httpproxies/HttpBasicsInterceptRequest.java` | 24 |
| ANY | `/clientSideFiltering/challenge-store/clientSideFiltering/challenge-store` | `` | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ShopEndpoint.java` | 23 |
| GET | `/clientSideFiltering/challenge-store/coupons/{code}` | `getDiscountCode` | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ShopEndpoint.java` | 53 |
| GET | `/clientSideFiltering/challenge-store/coupons` | `all` | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ShopEndpoint.java` | 61 |
| POST | `/clientSideFiltering/attack1` | `completed` | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ClientSideFilteringAssignment.java` | 27 |
| GET | `/clientSideFiltering/salaries` | `invoke` | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/Salaries.java` | 55 |
| POST | `/clientSideFiltering/getItForFree` | `completed` | `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/ClientSideFilteringFreeAssignment.java` | 31 |
| POST | `/PathTraversal/profile-upload` | `uploadFileHandler` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUpload.java` | 34 |
| GET | `/PathTraversal/profile-picture` | `` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUpload.java` | 46 |
| POST | `/PathTraversal/random` | `execute` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java` | 79 |
| GET | `/PathTraversal/random-picture` | `` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java` | 90 |
| POST | `/PathTraversal/profile-upload-fix` | `uploadFileHandler` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadFix.java` | 34 |
| GET | `/PathTraversal/profile-picture-fix` | `` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadFix.java` | 46 |
| POST | `/PathTraversal/profile-upload-remove-user-input` | `uploadFileHandler` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRemoveUserInput.java` | 33 |
| POST | `/PathTraversal/zip-slip` | `uploadFileHandler` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java` | 51 |
| GET | `/PathTraversal/zip-slip` | `` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java` | 97 |
| GET | `/PathTraversal/zip-slip/profile-image/{username}` | `` | `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java` | 103 |
| POST | `/crypto/encoding/xor` | `completed` | `src/main/java/org/owasp/webgoat/lessons/cryptography/XOREncodingAssignment.java` | 22 |
| ANY | `/crypto/signing/getprivate/crypto/signing/getprivate` | `getPrivateKey` | `src/main/java/org/owasp/webgoat/lessons/cryptography/SigningAssignment.java` | 37 |
| POST | `/crypto/signing/getprivate/crypto/signing/verify` | `completed` | `src/main/java/org/owasp/webgoat/lessons/cryptography/SigningAssignment.java` | 52 |
| ANY | `/crypto/hashing/md5/crypto/hashing/md5` | `getMd5` | `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java` | 30 |
| ANY | `/crypto/hashing/md5/crypto/hashing/sha256` | `getSha256` | `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java` | 49 |
| POST | `/crypto/hashing/md5/crypto/hashing` | `completed` | `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java` | 63 |
| GET | `/crypto/encoding/basic` | `getBasicAuth` | `src/main/java/org/owasp/webgoat/lessons/cryptography/EncodingAssignment.java` | 29 |
| POST | `/crypto/encoding/basic-auth` | `completed` | `src/main/java/org/owasp/webgoat/lessons/cryptography/EncodingAssignment.java` | 44 |
| POST | `/crypto/secure/defaults` | `completed` | `src/main/java/org/owasp/webgoat/lessons/cryptography/SecureDefaultsAssignment.java` | 27 |
| POST | `/LogSpoofing/log-spoofing` | `completed` | `src/main/java/org/owasp/webgoat/lessons/logging/LogSpoofingTask.java` | 21 |
| POST | `/LogSpoofing/log-bleeding` | `completed` | `src/main/java/org/owasp/webgoat/lessons/logging/LogBleedingTask.java` | 36 |
| POST | `/ChromeDevTools/dummy` | `completed` | `src/main/java/org/owasp/webgoat/lessons/chromedevtools/NetworkDummy.java` | 33 |
| POST | `/ChromeDevTools/network` | `completed` | `src/main/java/org/owasp/webgoat/lessons/chromedevtools/NetworkLesson.java` | 30 |
| POST | `/ChromeDevTools/network` | `` | `src/main/java/org/owasp/webgoat/lessons/chromedevtools/NetworkLesson.java` | 42 |
| POST | `/challenge/flag/{flagNumber}` | `postFlag` | `src/main/java/org/owasp/webgoat/lessons/challenges/FlagController.java` | 27 |
| POST | `/challenge/1` | `completed` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/Assignment1.java` | 28 |
| ANY | `/challenge/logo` | `logo` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge1/ImageServlet.java` | 23 |
| POST | `/challenge/5` | `login` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java` | 32 |
| GET | `/challenge/7/reset-password/{link}` | `resetPassword` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java` | 64 |
| POST | `/challenge/7` | `sendPasswordResetLink` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java` | 78 |
| GET | `/challenge/7/.git` | `git` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java` | 104 |
| GET | `/challenge/8/vote/{stars}` | `` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Assignment8.java` | 40 |
| GET | `/challenge/8/votes` | `` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Assignment8.java` | 58 |
| GET | `/challenge/8/votes/average` | `average` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Assignment8.java` | 65 |
| GET | `/challenge/8/notUsed` | `notUsed` | `src/main/java/org/owasp/webgoat/lessons/challenges/challenge8/Assignment8.java` | 76 |
| PUT | `/IDOR/profile/{userId}` | `completed` | `src/main/java/org/owasp/webgoat/lessons/idor/IDOREditOtherProfile.java` | 40 |
| POST | `/IDOR/profile/alt-path` | `completed` | `src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfileAltUrl.java` | 32 |
| GET | `/IDOR/profile/{userId}` | `completed` | `src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOtherProfile.java` | 39 |
| POST | `/IDOR/login` | `completed` | `src/main/java/org/owasp/webgoat/lessons/idor/IDORLogin.java` | 47 |
| GET | `/IDOR/own` | `invoke` | `src/main/java/org/owasp/webgoat/lessons/idor/IDORViewOwnProfile.java` | 25 |
| POST | `/IDOR/diff-attributes` | `completed` | `src/main/java/org/owasp/webgoat/lessons/idor/IDORDiffAttributes.java` | 26 |
| POST | `/HtmlTampering/task` | `completed` | `src/main/java/org/owasp/webgoat/lessons/htmltampering/HtmlTamperingTask.java` | 22 |
| POST | `/VulnerableComponents/attack1` | `completed` | `src/main/java/org/owasp/webgoat/lessons/vulnerablecomponents/VulnerableComponentsLesson.java` | 24 |
| POST | `/SqlInjectionAdvanced/attack6b` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java` | 31 |
| POST | `/SqlInjectionAdvanced/quiz` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionQuiz.java` | 30 |
| GET | `/SqlInjectionAdvanced/quiz` | `getResults` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionQuiz.java` | 67 |
| PUT | `/SqlInjectionAdvanced/register` | `registerNewUser` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java` | 42 |
| POST | `/SqlInjectionAdvanced/attack6a` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java` | 42 |
| POST | `/SqlInjectionAdvanced/login` | `login` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallengeLogin.java` | 26 |
| POST | `/SqlInjection/attack9` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson9.java` | 42 |
| POST | `/SqlInjection/attack5` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5.java` | 53 |
| POST | `/SqlInjection/assignment5b` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5b.java` | 37 |
| POST | `/SqlInjection/attack4` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson4.java` | 36 |
| POST | `/SqlInjection/attack3` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson3.java` | 35 |
| POST | `/SqlInjection/attack2` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson2.java` | 40 |
| POST | `/SqlInjection/attack10` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java` | 41 |
| POST | `/SqlInjection/assignment5a` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson5a.java` | 37 |
| POST | `/SqlInjection/attack8` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson8.java` | 41 |
| POST | `/SqlInjectionMitigations/attack10a` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10a.java` | 29 |
| POST | `/SqlOnlyInputValidation/attack` | `attack` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidation.java` | 29 |
| POST | `/SqlOnlyInputValidationOnKeywords/attack` | `attack` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlOnlyInputValidationOnKeywords.java` | 33 |
| POST | `/SqlInjectionMitigations/attack10b` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson10b.java` | 42 |
| ANY | `SqlInjectionMitigations/servers/SqlInjectionMitigations/servers` | `` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/Servers.java` | 25 |
| GET | `SqlInjectionMitigations/servers` | `sort` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/Servers.java` | 47 |
| POST | `/SqlInjectionMitigations/attack12a` | `completed` | `src/main/java/org/owasp/webgoat/lessons/sqlinjection/mitigation/SqlInjectionLesson13.java` | 41 |
| POST | `/BypassRestrictions/FieldRestrictions` | `completed` | `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFieldRestrictions.java` | 20 |
| POST | `/BypassRestrictions/frontendValidation` | `completed` | `src/main/java/org/owasp/webgoat/lessons/bypassrestrictions/BypassRestrictionsFrontendValidation.java` | 20 |
| POST | `/csrf/feedback/message` | `completed` | `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFFeedback.java` | 41 |
| POST | `/csrf/feedback` | `flag` | `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFFeedback.java` | 69 |
| POST | `/csrf/basic-get-flag` | `invoke` | `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFGetFlag.java` | 25 |
| POST | `/csrf/login` | `completed` | `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFLogin.java` | 22 |
| GET | `/csrf/review` | `retrieveReviews` | `src/main/java/org/owasp/webgoat/lessons/csrf/ForgedReviews.java` | 53 |
| POST | `/csrf/review` | `createNewReview` | `src/main/java/org/owasp/webgoat/lessons/csrf/ForgedReviews.java` | 70 |
| POST | `/csrf/confirm-flag-1` | `completed` | `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFConfirmFlag1.java` | 29 |
| POST | `/InsecureLogin/task` | `completed` | `src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLoginTask.java` | 18 |
| POST | `/InsecureLogin/login` | `login` | `src/main/java/org/owasp/webgoat/lessons/insecurelogin/InsecureLoginTask.java` | 27 |
| GET | `/` | `logRequest` | `src/main/java/org/owasp/webgoat/lessons/xxe/Ping.java` | 24 |
| POST | `/xxe/content-type` | `createNewUser` | `src/main/java/org/owasp/webgoat/lessons/xxe/ContentTypeAssignment.java` | 45 |
| ANY | `xxe/comments/xxe/comments` | `` | `src/main/java/org/owasp/webgoat/lessons/xxe/CommentsEndpoint.java` | 22 |
| GET | `xxe/comments` | `retrieveComments` | `src/main/java/org/owasp/webgoat/lessons/xxe/CommentsEndpoint.java` | 28 |
| POST | `/xxe/simple` | `createNewComment` | `src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java` | 48 |
| ANY | `/xxe/sampledtd` | `getSampleDTDFile` | `src/main/java/org/owasp/webgoat/lessons/xxe/SimpleXXE.java` | 77 |
| POST | `/xxe/blind` | `addComment` | `src/main/java/org/owasp/webgoat/lessons/xxe/BlindSendFileAssignment.java` | 67 |
| POST | `/SecurePasswords/assignment` | `completed` | `src/main/java/org/owasp/webgoat/lessons/securepasswords/SecurePasswordsAssignment.java` | 25 |
| GET | `/CrossSiteScripting/attack5a` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson5a.java` | 42 |
| POST | `/CrossSiteScripting/attack6a` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson6a.java` | 34 |
| POST | `/CrossSiteScripting/phone-home-xss` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/DOMCrossSiteScripting.java` | 29 |
| POST | `/CrossSiteScripting/quiz` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingQuiz.java` | 27 |
| GET | `/CrossSiteScripting/quiz` | `getResults` | `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingQuiz.java` | 64 |
| POST | `/CrossSiteScripting/attack1` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/CrossSiteScriptingLesson1.java` | 20 |
| POST | `/CrossSiteScripting/dom-follow-up` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/DOMCrossSiteScriptingVerifier.java` | 38 |
| GET | `/CrossSiteScriptingStored/stored-xss` | `retrieveComments` | `src/main/java/org/owasp/webgoat/lessons/xss/stored/StoredXssComments.java` | 57 |
| POST | `/CrossSiteScriptingStored/stored-xss` | `createNewComment` | `src/main/java/org/owasp/webgoat/lessons/xss/stored/StoredXssComments.java` | 73 |
| POST | `/CrossSiteScriptingStored/stored-xss-follow-up` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/stored/StoredCrossSiteScriptingVerifier.java` | 28 |
| POST | `/CrossSiteScripting/attack4` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/mitigation/CrossSiteScriptingLesson4.java` | 22 |
| POST | `/CrossSiteScripting/attack3` | `completed` | `src/main/java/org/owasp/webgoat/lessons/xss/mitigation/CrossSiteScriptingLesson3.java` | 30 |
| POST | `/HijackSession/login` | `login` | `src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java` | 47 |
| POST | `/JWT/refresh/login` | `follow` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java` | 49 |
| POST | `/JWT/refresh/checkout` | `checkout` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java` | 83 |
| POST | `/JWT/refresh/newToken` | `newToken` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java` | 108 |
| POST | `/JWT/decode` | `decode` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTDecodeEndpoint.java` | 20 |
| ANY | `/JWT/secret/gettoken/JWT/secret/gettoken` | `getSecretToken` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java` | 43 |
| POST | `/JWT/secret/gettoken/JWT/secret` | `login` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java` | 59 |
| GET | `/JWT/votings/login` | `login` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java` | 103 |
| GET | `/JWT/votings` | `getVotes` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java` | 126 |
| POST | `/JWT/votings/{title}` | `` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java` | 154 |
| POST | `/JWT/votings` | `resetVotes` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java` | 179 |
| POST | `/JWT/quiz` | `completed` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTQuiz.java` | 24 |
| GET | `/JWT/quiz` | `getResults` | `src/main/java/org/owasp/webgoat/lessons/jwt/JWTQuiz.java` | 50 |
| ANY | `/JWT/JWT` | `` | `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java` | 29 |
| POST | `/JWT/jku/follow/{user}` | `follow` | `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java` | 40 |
| POST | `/JWT/jku/delete` | `resetVotes` | `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java` | 49 |
| ANY | `/JWT/JWT` | `JWTHeaderKIDEndpoint` | `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java` | 40 |
| POST | `/JWT/kid/follow/{user}` | `follow` | `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java` | 48 |
| POST | `/JWT/kid/delete` | `resetVotes` | `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java` | 57 |
| POST | `/InsecureDeserialization/task` | `completed` | `src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java` | 32 |
| ANY | `/file-server-location` | `getFileLocation` | `src/main/java/org/owasp/webgoat/webwolf/FileServer.java` | 56 |
| POST | `/fileupload` | `importFile` | `src/main/java/org/owasp/webgoat/webwolf/FileServer.java` | 65 |
| GET | `/files` | `getFiles` | `src/main/java/org/owasp/webgoat/webwolf/FileServer.java` | 86 |
| GET | `/mail` | `mail` | `src/main/java/org/owasp/webgoat/webwolf/mailbox/MailboxController.java` | 26 |
| POST | `/mail` | `sendEmail` | `src/main/java/org/owasp/webgoat/webwolf/mailbox/MailboxController.java` | 40 |
| DELETE | `/mail` | `deleteAllMail` | `src/main/java/org/owasp/webgoat/webwolf/mailbox/MailboxController.java` | 46 |
| GET | `/jwt` | `jwt` | `src/main/java/org/owasp/webgoat/webwolf/jwt/JWTController.java` | 20 |
| POST | `/jwt/decode` | `decode` | `src/main/java/org/owasp/webgoat/webwolf/jwt/JWTController.java` | 25 |
| POST | `/jwt/encode` | `encode` | `src/main/java/org/owasp/webgoat/webwolf/jwt/JWTController.java` | 35 |
| ANY | `/landing/**/landing/**` | `` | `src/main/java/org/owasp/webgoat/webwolf/requests/LandingPage.java` | 17 |
| ANY | `/landing/**` | `` | `src/main/java/org/owasp/webgoat/webwolf/requests/LandingPage.java` | 20 |
| ANY | `/requests/requests` | `` | `src/main/java/org/owasp/webgoat/webwolf/requests/Requests.java` | 31 |
| GET | `/requests` | `get` | `src/main/java/org/owasp/webgoat/webwolf/requests/Requests.java` | 45 |

## Security-Relevant Patterns

### Database (69 matches)

- **JdbcTemplate** — 7 hit(s) in: `src/main/java/org/owasp/webgoat/container/users/UserService.java`, `src/main/java/org/owasp/webgoat/lessons/missingac/MissingAccessControlUserRepository.java`, `src/test/java/org/owasp/webgoat/container/users/UserServiceTest.java`
- **JDBC/Statement** — 51 hit(s) in: `src/it/java/org/owasp/webgoat/integration/SqlInjectionMitigationIntegrationTest.java`, `src/main/java/org/owasp/webgoat/container/lessons/LessonConnectionInvocationHandler.java`, `src/main/java/org/owasp/webgoat/lessons/challenges/challenge5/Assignment5.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java`
  …and 15 more files
- **SQL string concat** — 10 hit(s) in: `src/it/java/org/owasp/webgoat/integration/JWTLessonIntegrationTest.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionChallenge.java`, `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6a.java`, `src/main/java/org/owasp/webgoat/lessons/sqlinjection/introduction/SqlInjectionLesson10.java`
  …and 4 more files
- **DriverManager** — 1 hit(s) in: `src/it/java/org/owasp/webgoat/integration/SqlInjectionMitigationIntegrationTest.java`

### Deserialization (21 matches)

- **XStream** — 6 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/vulnerablecomponents/VulnerableComponentsLesson.java`, `src/test/java/org/owasp/webgoat/lessons/vulnerablecomponents/VulnerableComponentsLessonTest.java`
- **ObjectInputStream** — 9 hit(s) in: `src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java`, `src/main/java/org/owasp/webgoat/lessons/deserialization/InsecureDeserializationTask.java`, `src/main/java/org/owasp/webgoat/lessons/deserialization/SerializationHelper.java`
- **Serializable** — 6 hit(s) in: `src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java`, `src/main/java/org/owasp/webgoat/container/session/LabelDebugger.java`, `src/main/java/org/owasp/webgoat/lessons/challenges/Email.java`, `src/main/java/org/owasp/webgoat/lessons/passwordreset/PasswordResetEmail.java`, `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/Email.java`
  …and 1 more files

### Command Execution (1 matches)

- **Runtime.exec** — 1 hit(s) in: `src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java`

### File Handling (95 matches)

- **MultipartFile** — 24 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUpload.java`, `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadBase.java`, `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadFix.java`, `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRemoveUserInput.java`, `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java`
  …and 4 more files
- **File I/O** — 55 hit(s) in: `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`, `src/it/java/org/owasp/webgoat/integration/LabelAndHintIntegrationTest.java`, `src/it/java/org/owasp/webgoat/integration/PathTraversalIntegrationTest.java`, `src/main/java/org/owasp/webgoat/container/WebGoat.java`, `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/MD5.java`
  …and 10 more files
- **ZipEntry** — 9 hit(s) in: `src/it/java/org/owasp/webgoat/integration/PathTraversalIntegrationTest.java`, `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java`
- **Path traversal risk** — 7 hit(s) in: `src/it/java/org/owasp/webgoat/integration/CSRFIntegrationTest.java`, `src/it/java/org/owasp/webgoat/integration/PathTraversalIntegrationTest.java`, `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileUploadRetrieval.java`, `src/main/java/org/owasp/webgoat/lessons/pathtraversal/ProfileZipSlip.java`, `src/main/java/org/owasp/webgoat/webwolf/FileServer.java`

### Xml Parsing (2 matches)

- **XMLReader** — 2 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/xxe/CommentsCache.java`

### Authentication (62 matches)

- **AuthenticationManager** — 21 hit(s) in: `src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java`, `src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java`, `src/main/java/org/owasp/webgoat/lessons/hijacksession/cas/AuthenticationProvider.java`, `src/main/java/org/owasp/webgoat/lessons/hijacksession/cas/HijackSessionAuthenticationProvider.java`, `src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java`
  …and 2 more files
- **Login form** — 23 hit(s) in: `src/it/java/org/owasp/webgoat/playwright/webgoat/LoginUITest.java`, `src/it/java/org/owasp/webgoat/playwright/webgoat/RegistrationUITest.java`, `src/it/java/org/owasp/webgoat/playwright/webgoat/helpers/Authentication.java`, `src/it/java/org/owasp/webgoat/playwright/webwolf/LoginUITest.java`, `src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java`
  …and 1 more files
- **UserDetailsService** — 12 hit(s) in: `src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java`, `src/main/java/org/owasp/webgoat/container/users/UserService.java`, `src/main/java/org/owasp/webgoat/container/users/WebGoatUser.java`, `src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java`, `src/main/java/org/owasp/webgoat/webwolf/user/UserService.java`
  …and 1 more files
- **PasswordEncoder** — 6 hit(s) in: `src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java`, `src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java`

### Authorization (6 matches)

- **antMatchers/requestMatchers** — 6 hit(s) in: `src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java`, `src/main/java/org/owasp/webgoat/webwolf/WebSecurityConfig.java`

### Session (49 matches)

- **Cookie** — 23 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/csrf/CSRFFeedback.java`, `src/main/java/org/owasp/webgoat/lessons/hijacksession/HijackSessionAssignment.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/spoofcookie/SpoofCookieAssignment.java`, `src/test/java/org/owasp/webgoat/lessons/csrf/CSRFFeedbackTest.java`
  …and 3 more files
- **HttpSession** — 25 hit(s) in: `src/main/java/org/owasp/webgoat/container/AsciiDoctorTemplateResolver.java`, `src/main/java/org/owasp/webgoat/container/WebSecurityConfig.java`, `src/main/java/org/owasp/webgoat/container/controller/Welcome.java`, `src/main/java/org/owasp/webgoat/lessons/cryptography/EncodingAssignment.java`, `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java`
  …and 3 more files
- **CSRF config** — 1 hit(s) in: `src/test/java/org/owasp/webgoat/webwolf/mailbox/MailboxControllerTest.java`

### Cryptography (26 matches)

- **Hardcoded key/secret** — 13 hit(s) in: `src/it/java/org/owasp/webgoat/playwright/webgoat/RegistrationUITest.java`, `src/it/java/org/owasp/webgoat/playwright/webwolf/JwtUITest.java`, `src/main/java/org/owasp/webgoat/lessons/challenges/SolutionConstants.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/sqlinjection/advanced/SqlInjectionLesson6b.java`
  …and 5 more files
- **KeyGenerator** — 6 hit(s) in: `src/it/java/org/owasp/webgoat/integration/JWTLessonIntegrationTest.java`, `src/main/java/org/owasp/webgoat/lessons/cryptography/CryptoUtil.java`, `src/test/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpointTest.java`
- **MessageDigest** — 3 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/cryptography/HashingAssignment.java`, `src/main/java/org/owasp/webgoat/lessons/missingac/DisplayUser.java`
- **SecureRandom** — 4 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/cryptography/CryptoUtil.java`, `src/main/java/org/owasp/webgoat/lessons/xss/DOMCrossSiteScripting.java`

### Redirect (7 matches)

- **redirect:** — 4 hit(s) in: `src/main/java/org/owasp/webgoat/container/HammerHead.java`, `src/main/java/org/owasp/webgoat/container/WebWolfRedirect.java`, `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java`
- **forward:** — 1 hit(s) in: `src/main/java/org/owasp/webgoat/container/controller/Welcome.java`
- **RedirectView** — 2 hit(s) in: `src/main/java/org/owasp/webgoat/webwolf/FileServer.java`

### Template Rendering (83 matches)

- **Thymeleaf** — 37 hit(s) in: `src/main/java/org/owasp/webgoat/container/AsciiDoctorTemplateResolver.java`, `src/main/java/org/owasp/webgoat/container/LessonResourceScanner.java`, `src/main/java/org/owasp/webgoat/container/LessonTemplateResolver.java`, `src/main/java/org/owasp/webgoat/container/MvcConfiguration.java`, `src/main/java/org/owasp/webgoat/container/WebGoat.java`
  …and 7 more files
- **ModelAndView** — 46 hit(s) in: `src/main/java/org/owasp/webgoat/container/HammerHead.java`, `src/main/java/org/owasp/webgoat/container/UserInterceptor.java`, `src/main/java/org/owasp/webgoat/container/WebWolfRedirect.java`, `src/main/java/org/owasp/webgoat/container/controller/StartLesson.java`, `src/main/java/org/owasp/webgoat/container/controller/Welcome.java`
  …and 8 more files

### Http Client (20 matches)

- **RestTemplate** — 18 hit(s) in: `src/main/java/org/owasp/webgoat/container/WebGoat.java`, `src/main/java/org/owasp/webgoat/lessons/challenges/challenge7/Assignment7.java`, `src/main/java/org/owasp/webgoat/lessons/passwordreset/ResetLinkAssignmentForgotPassword.java`, `src/main/java/org/owasp/webgoat/lessons/passwordreset/SimpleMailAssignment.java`, `src/main/java/org/owasp/webgoat/lessons/webwolfintroduction/MailAssignment.java`
  …and 1 more files
- **URL constructor** — 2 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderJKUEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/ssrf/SSRFTask2.java`

### Jwt (51 matches)

- **JWT parsing** — 38 hit(s) in: `src/it/java/org/owasp/webgoat/integration/JWTLessonIntegrationTest.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/JWTSecretKeyEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/JWTVotesEndpoint.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/claimmisuse/JWTHeaderKIDEndpoint.java`
  …and 6 more files
- **JWT token** — 13 hit(s) in: `src/it/java/org/owasp/webgoat/integration/JWTLessonIntegrationTest.java`, `src/main/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpoint.java`, `src/test/java/org/owasp/webgoat/lessons/jwt/JWTRefreshEndpointTest.java`

### Logging Sensitive (4 matches)

- **Log injection risk** — 4 hit(s) in: `src/main/java/org/dummy/insecure/framework/VulnerableTaskHolder.java`, `src/main/java/org/owasp/webgoat/container/users/RegistrationController.java`, `src/main/java/org/owasp/webgoat/lessons/missingac/MissingFunctionACUsers.java`, `src/main/java/org/owasp/webgoat/webwolf/requests/LandingPage.java`

### Reflection (4 matches)

- **Method.invoke** — 1 hit(s) in: `src/main/java/org/owasp/webgoat/container/lessons/LessonConnectionInvocationHandler.java`
- **newInstance** — 3 hit(s) in: `src/main/java/org/owasp/webgoat/lessons/clientsidefiltering/Salaries.java`, `src/main/java/org/owasp/webgoat/lessons/xxe/CommentsCache.java`

## Summary

- Lesson modules: 30
- Spring components: 183
  - configuration: 10
  - controller: 125
  - component: 45
  - service: 2
  - repository: 1
- REST endpoints: 189
- Security patterns detected: 500
  - database: 69
  - deserialization: 21
  - command_execution: 1
  - file_handling: 95
  - xml_parsing: 2
  - authentication: 62
  - authorization: 6
  - session: 49
  - cryptography: 26
  - redirect: 7
  - template_rendering: 83
  - http_client: 20
  - jwt: 51
  - logging_sensitive: 4
  - reflection: 4

