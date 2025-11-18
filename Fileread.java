private static String readJsonFileSafely(String inputPath) throws IOException {
    Logger LOGGER = LoggerFactory.getLogger(SecretEncryptor.class);

    // Validate input
    if (inputPath == null || inputPath.trim().isEmpty()) {
        throw new IllegalArgumentException("Input JSON file path cannot be null or empty");
    }

    // Normalize path & remove traversal issues
    Path jsonPath = Paths.get(inputPath).normalize();

    // Enforce directory restriction (Fortify requirement)
    Path allowedDir = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();
    jsonPath = jsonPath.toAbsolutePath().normalize();

    if (!jsonPath.startsWith(allowedDir)) {
        throw new SecurityException("Access denied: file must be inside application directory");
    }

    if (!Files.exists(jsonPath) || !Files.isReadable(jsonPath)) {
        throw new FileNotFoundException("JSON file not found or not readable");
    }

    // Limit file size (Fortify requires size check)
    long maxAllowedSize = 5 * 1024 * 1024; // 5 MB
    long fileSize = Files.size(jsonPath);

    if (fileSize > maxAllowedSize) {
        throw new SecurityException("Input JSON file too large: " + fileSize);
    }

    // Safe streaming read - NO readAllBytes(), NO FileReader
    StringBuilder sb = new StringBuilder();

    try (BufferedReader reader = Files.newBufferedReader(jsonPath, StandardCharsets.UTF_8)) {
        char[] buffer = new char[4096];
        int read;
        while ((read = reader.read(buffer)) != -1) {
            sb.append(buffer, 0, read);
        }
    }

    LOGGER.info("JSON file loaded successfully from: {}", jsonPath);
    return sb.toString();
}
