package com.yourcompany.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;

public class SecretEncryptorNio {

    private static final Logger LOGGER = LoggerFactory.getLogger(SecretEncryptorNio.class);

    public static void main(String[] args) {

        if (args == null || args.length != 1) {
            LOGGER.error("Requires one argument: path to JSON file");
            System.exit(6);
        }

        String jsonFileName = args[0];

        // Resolve & validate using NIO (no java.io.File usage)
        Path safeBaseDir;
        Path resolvedInputPath;

        try {
            // Resolve trusted base directory (application working dir)
            safeBaseDir = Paths.get(System.getProperty("user.dir"))
                               .toAbsolutePath()
                               .normalize()
                               .toRealPath(LinkOption.NOFOLLOW_LINKS);

            // Resolve the candidate path (the untrusted input) in a safe manner
            Path candidate = Paths.get(jsonFileName)
                                  .toAbsolutePath()
                                  .normalize();

            // toRealPath will resolve symlinks and throw if file doesn't exist
            resolvedInputPath = candidate.toRealPath(LinkOption.NOFOLLOW_LINKS);

        } catch (IOException e) {
            LOGGER.error("Failed to resolve paths: {}", e.getMessage());
            System.exit(6);
            return;
        }

        // Verify the input path is inside the safe base directory
        if (!resolvedInputPath.startsWith(safeBaseDir)) {
            LOGGER.error("File is outside the allowed directory: {}", resolvedInputPath);
            System.exit(6);
        }

        // Verify it's a regular readable file
        if (!Files.isRegularFile(resolvedInputPath, LinkOption.NOFOLLOW_LINKS) ||
            !Files.isReadable(resolvedInputPath)) {
            LOGGER.error("Target is not a regular readable file: {}", resolvedInputPath);
            System.exit(6);
        }

        // Read file content using NIO InputStream (no File objects)
        String jsonContent;
        try (InputStream in = Files.newInputStream(resolvedInputPath, StandardOpenOption.READ)) {
            byte[] bytes = in.readAllBytes(); // Java 9+; for Java 8 use a loop or ByteArrayOutputStream
            jsonContent = new String(bytes, StandardCharsets.UTF_8);
        } catch (IOException e) {
            LOGGER.error("Error reading file {}: {}", resolvedInputPath, e.getMessage());
            System.exit(6);
            return;
        }

        // Parse JSON into map (your existing safe method)
        HashMap<String, Object> map = createHashMapFromJsonString(jsonContent, "*");
        LOGGER.info("Parsed map size: {}", map.size());
    }

    /**
     * Placeholder for your JSON -> HashMap conversion.
     * Refactor if needed to use a safe JSON library (Jackson/Gson) and avoid insecure deserialization.
     */
    private static HashMap<String, Object> createHashMapFromJsonString(String json, String prefix) {
        // TODO: replace with real implementation
        return new HashMap<>();
    }
}
