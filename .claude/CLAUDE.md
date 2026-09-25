# Project Instructions

## GoLang Coding Standards

- write .md files into a subfolder ./docs/
- when writing unit tests, use t.Logf() to log program input and output
- never remove ToDo comments unless fully implemented
- write private functions at the end of the file after public functions
- when returning new `MsgCode` strings on errors, ensure translations in `locales` folder are updated
- use `uint64` as Primary Keys and put GORM default time columns at the end of the table 

## ed2k Protocol

- ensure your implementation is compatible with latest C++ client at `/Users/daniel/Documents/Coding/CPP/eMuleQt/src` and original client at `/Users/daniel/Documents/Coding/CPP/eMuleQt/srchybrid`

## Project

- when adding new keys to `config.example.yaml` always add them to all other config files too