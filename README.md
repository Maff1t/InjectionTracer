# InjectionTracer

InjectionTracer is a PIN tool that aims to help  the analysis of malware that uses process injection to:

- Rapidly understand the injection technique used
- Debugging the injected code → The execution stops when the remote thread is executed
- Dumping the injected code and fix PE Image on disk (Imagebase and section alignment)
- Redirect the injection into another process (-redirect)

## Usage

![Demo](Media/demo.gif)