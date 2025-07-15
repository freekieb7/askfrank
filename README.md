# Project Overview

This project is a simple web application built using the Fiber web framework in Go. It serves as an introductory example of how to set up a basic HTTP server that responds with "Hello, World!" when accessed.

## Getting Started

To get a local copy up and running, follow these steps.

### Prerequisites

- Go (version 1.16 or later)
- Git

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/yourusername/[project-name].git
   ```

2. Navigate to the project directory:
   ```
   cd [project-name]
   ```

3. Install the dependencies:
   ```
   go mod tidy
   ```

### Running the Application

To run the application, use the following command:
```
go run src/main.go
```

The server will start on `localhost:3000`. You can access it by navigating to `http://localhost:3000` in your web browser.

### CI/CD Pipeline

This project includes a CI/CD pipeline defined in `.github/workflows/ci.yml`. The pipeline runs on push events to the main branch, setting up the Go environment, installing dependencies, running tests, and building the application.

## Contributing

Contributions are welcome! Please feel free to submit a pull request or open an issue for any suggestions or improvements.

## License

This project is licensed under the MIT License. See the LICENSE file for details.