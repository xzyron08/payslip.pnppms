# Phishing Detection System

A Python-based phishing detection system that analyzes URLs and web content to identify potential phishing attempts. This system uses machine learning and various security checks to evaluate the legitimacy of websites.

## Project Goal

The primary goal of this phishing detection system is to:

1. **Prevent Phishing Attacks**: Identify and flag potential phishing websites before they can cause harm to users and organizations.

2. **Protect Users**: Provide an automated tool that helps users verify the legitimacy of websites they visit, reducing the risk of falling victim to phishing scams.

3. **Enhance Security**: Implement multiple layers of security checks including:
   - URL analysis
   - Content verification
   - Domain reputation checking
   - SSL certificate validation
   - Machine learning-based detection

4. **Educate Users**: Help users understand the characteristics of phishing websites and how to identify them.

5. **Support Organizations**: Provide a tool that organizations can use to:
   - Scan their domains for potential phishing attempts
   - Monitor for unauthorized use of their brand
   - Protect their customers and employees from phishing attacks

6. **Research and Development**: Contribute to the field of cybersecurity by:
   - Developing new detection methods
   - Improving existing phishing detection techniques
   - Creating a dataset of phishing indicators

This project aims to be a comprehensive solution for phishing detection while maintaining high accuracy and minimizing false positives.

## Features

- URL Analysis
  - Domain age checking
  - SSL certificate verification
  - Domain reputation checking
  - URL structure analysis
  - IP address detection
  - WHOIS information retrieval

- Content Analysis
  - HTML content extraction
  - Form detection
  - Input field analysis
  - JavaScript code analysis
  - External resource detection
  - Content similarity checking

- Machine Learning Integration
  - Feature extraction
  - Model-based prediction
  - Confidence scoring

## Prerequisites

- Python 3.8 or higher
- Required Python packages (install using `pip install -r requirements.txt`):
  - requests
  - beautifulsoup4
  - python-whois
  - scikit-learn
  - pandas
  - numpy
  - urllib3
  - ssl
  - socket
  - re
  - datetime

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/phishing-python.git
cd phishing-python
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```python
from phishing_detector import PhishingDetector

# Initialize the detector
detector = PhishingDetector()

# Analyze a URL
url = "https://example.com"
result = detector.analyze_url(url)

# Print results
print(result)
```

### Advanced Usage

```python
from phishing_detector import PhishingDetector

# Initialize with custom settings
detector = PhishingDetector(
    check_ssl=True,
    check_domain_age=True,
    check_domain_reputation=True,
    analyze_content=True
)

# Analyze multiple URLs
urls = [
    "https://example1.com",
    "https://example2.com"
]

for url in urls:
    result = detector.analyze_url(url)
    print(f"Analysis for {url}:")
    print(result)
```

## Project Structure

```
phishing-python/
├── phishing_detector.py    # Main detection logic
├── requirements.txt        # Project dependencies
├── README.md              # This documentation
└── tests/                 # Test files
```

## Features in Detail

### URL Analysis
- Checks domain age using WHOIS information
- Verifies SSL certificate validity
- Analyzes domain reputation
- Examines URL structure for suspicious patterns
- Detects IP addresses in URLs
- Retrieves WHOIS information

### Content Analysis
- Extracts and analyzes HTML content
- Identifies forms and input fields
- Examines JavaScript code for suspicious patterns
- Detects external resources
- Performs content similarity analysis

### Machine Learning
- Extracts relevant features from URLs and content
- Uses trained models for prediction
- Provides confidence scores for predictions

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is for educational and research purposes only. Always verify the results manually and use this tool responsibly.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 

## Created by

Jacques Nico L. Belmonte  || Intern - Camarines Sur Polytechnic Colleges - Bachelor of Science in Computer Science