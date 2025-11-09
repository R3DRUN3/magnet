# Magnet  

[![License: Unlicense](https://img.shields.io/badge/license-Unlicense-blue.svg)](http://unlicense.org/)  ![language](https://img.shields.io/badge/poweredby-rust-orange) ![Red Team Badge](https://img.shields.io/badge/Team-Red-red) ![Purple Team Badge](https://img.shields.io/badge/Team-Purple-purple)

<img src="./media/logo.png" alt="Magnet Logo" width="200">  


> Draw the Signals, Detect the Threats.  

Magnet is Purple-team telemetry & simulation toolkit.

**Purpose:** modular, cross-platform (eventually) generator for benign telemetry and purple-team exercises.


## Quickstart

Compile:

For Windows: 
```bash
cargo build --target x86_64-pc-windows-msvc --release
```  



For Linux: 
```bash
cargo build --target x86_64-unknown-linux-gnu --release
```  

Each binary only includes the modules for that platform.


list modules
```bash
magnet list
``` 

```bash
magnet run windows all
```   


```bash
magnet run windows discovery_sim
```  



## tests
```bash
cargo test --test ransom_note_test
```  

![ransom_note_test](./media/ransom_note_unit_test.png)  


