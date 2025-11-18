public static String readJsonFileSafely(String[] args) throws IOException {
    Logger LOGGER = LoggerFactory.getLogger(SecretEncryptor.class);

    // Validate arguments
    if (args == null || args.length == 0) {
        throw new IllegalArgumentException("At least one argument (JSON file path) is required");
    }

    // Extract path string from array
    String inputPath = args[0];

    if (inputPath == null || inputPath.trim().isEmpty()) {
        throw new IllegalArgumentException("JSON file path cannot be null or empty");
    }

    // Normalize input
    Path jsonPath = Paths.get(inputPath).normalize();

    // Restrict directory access
    Path allowedDir = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
    jsonPath = jsonPath.toAbsolutePath().normalize();

    if (!jsonPath.startsWith(allowedDir)) {
        throw new SecurityException("Access denied: file must be inside application directory");
    }

    // Basic checks
    if (!Files.exists(jsonPath)) {
        throw new FileNotFoundException("JSON file not found: " + jsonPath);
    }

    if (!Files.isReadable(jsonPath)) {
        throw new IOException("JSON file is not readable: " + jsonPath);
    }

    // File size limit (Fortify requirement)
    long maxAllowedSize = 5 * 1024 * 1024; // 5 MB
    long fileSize = Files.size(jsonPath);
    if (fileSize > maxAllowedSize) {
        throw new SecurityException("JSON file too large: " + fileSize);
    }

    // Safe streaming read (NO readAllBytes)
    StringBuilder sb = new StringBuilder();
    try (BufferedReader reader = Files.newBufferedReader(jsonPath, StandardCharsets.UTF_8)) {
        char[] buffer = new char[4096];
        int read;
        while ((read = reader.read(buffer)) != -1) {
            sb.append(buffer, 0, read);
        }
    }

    LOGGER.info("JSON loaded successfully from: {}", jsonPath);
    return sb.toString();
}
