# VDScannerX

<div align="center">
<img src="/ScreenShots/Home_interface.png" width="800" height="450" alt="Main Interface">
<img src="/ScreenShots/Analysis_Result.png" width="800" height="450" alt="Analysis Results">
<img src="/ScreenShots/Report_Generation.png" width="800" height="450" alt="Report Generation">
<img src="/ScreenShots/HTML_Export.jpeg" width="800" alt="HTML Export">
<img src="/ScreenShots/Dark_Mode.png" width="800" height="450" alt="Dark Mode Interface">
</div>

## Table of Contents

- [Overview](#overview)
- [Features](#features)
  - [Analysis Capabilities](#analysis-capabilities)
  - [User Interface](#user-interface)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Usage](#usage)
- [Code Structure](#code-structure)
- [License](#license)

## Overview

VDScannerX is a powerful desktop application built in Python for analyzing potential malware files. The tool provides detailed analysis of executable files through both static and dynamic analysis, leveraging VirusTotal's powerful API for comprehensive threat detection. Built with a modern GUI using CustomTkinter, it offers an intuitive interface for both security professionals and researchers, complete with dark mode support for comfortable viewing in any environment.

## Features

### Analysis Capabilities

- **Static Analysis via VirusTotal**:
  - File hash verification against VirusTotal database
  - Multiple antivirus engine results
  - File reputation scoring
  - Historical detection data
- **Dynamic Analysis Features**:
  - Real-time behavior monitoring
  - Network connection tracking
  - System changes detection
  - Process creation monitoring
- **PE File Analysis**:
  - Deep inspection of Portable Executable file structures
  - Header analysis
  - Import/Export table examination
  - Section analysis

### User Interface

- **Modern GUI Interface**: Clean and intuitive interface built with CustomTkinter
- **Dark/Light Mode Toggle**: Comfortable viewing experience in any lighting condition
- **Real-time Analysis Updates**: Live progress indicators during scanning
- **Interactive Results Display**: Easy-to-navigate analysis results
- **Detailed Reporting**: Generate comprehensive PDF reports of analysis results
- **HTML Export**: Export analysis results to interactive HTML reports with:
  - Collapsible sections
  - Mobile-responsive design

## Getting Started

### Prerequisites

- Python 3 or higher
- Windows Operating System
- Internet connection for dependency installation
- VirusTotal API key (free or premium)
- Hybird Analysis API Key

### Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/yourusername/VDScannerX.git
   cd VDScannerX
   ```

2. **Create Virtual Environment (Recommended)**

   ```bash
   python -m venv venv
   .\venv\Scripts\activate
   ```

3. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```
4. **Configure API Keys**
   ```bash
    Open Config.py and update your VirusTotal API &
    Hybird Analysis API
   ```

## Usage

1. **Launch the Application**

   ```bash
   python main.py
   ```

2. **Configure Theme**

   - Use the theme toggle button in the top-right corner to switch between light and dark modes
   - Your preference will be saved for future sessions

3. **Analyze a File**

   - Click "Select File" to choose the executable for analysis
   - Select analysis type:
     - Quick Scan: Static analysis using VirusTotal
     - Deep Scan: Combined static and dynamic analysis
   - View real-time analysis progress
   - Review comprehensive results in the main interface

4. **Generate Report**
   - After analysis, click "Generate Report"
   - Choose report format:
     - PDF: Comprehensive static report
     - HTML: Interactive web-based report
   - The report includes:
     - VirusTotal analysis results
     - Dynamic behavior analysis
     - PE file structure details
     - Network activity summary
   - HTML reports feature:
     - Interactive data visualization
     - Expandable technical details
     - Full-text search capability
     - Easy sharing via web browsers

## Code Structure

- **gui/**  
  Contains all GUI-related code using CustomTkinter

- **analyzer/**  
  Core analysis logic and PE file processing

- **report/**  
  Report generation functionality using ReportLab

- **utils/**  
  Helper functions and utility modules

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

**Note**: This tool is for educational and research purposes only. Always exercise caution when analyzing potentially malicious files. Some features require a VirusTotal API key, and usage limits may apply based on your subscription type.
