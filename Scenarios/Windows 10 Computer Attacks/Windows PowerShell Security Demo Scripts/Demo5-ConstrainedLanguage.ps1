[System.Console]::WriteLine("Evil")

pause

$ExecutionContext.SessionState.LanguageMode = "ConstrainedLanguage"
[System.Console]::WriteLine("Evil")

pause