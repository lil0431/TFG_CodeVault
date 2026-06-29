package com.godfathercapybara.capybara.service;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import com.godfathercapybara.capybara.model.Analysis;
import com.godfathercapybara.capybara.model.User;
import com.godfathercapybara.capybara.repository.AnalysisRepository;

@Service
public class BinaryAnalysisService {

    private static final Logger logger = LoggerFactory.getLogger(BinaryAnalysisService.class);

    @Autowired
    private AnalysisRepository analysisRepository;

    // Rutas del servidor Ubuntu
    private static final String PYTHON_EXECUTABLE = "python3";
    private static final String TFG_DIRECTORY = "./scripts/";
    private static final String ORQUESTADOR_SCRIPT = "tfg_orchestrator.py";

    public Analysis analyzeBinary(User user, MultipartFile file, String apiKey, String engine,
                                   boolean explain, boolean aiVulns, boolean exploit, boolean mitigate,
                                   boolean scan, boolean asmOnly) throws Exception {

        logger.info("=== INICIANDO ANÁLISIS: {} ===", file.getOriginalFilename());

        if (file.isEmpty()) {
            throw new IllegalArgumentException("El archivo no puede estar vacío");
        }

        byte[] fileBytes = file.getBytes();
        if (!isBinaryFile(fileBytes)) {
            throw new IllegalArgumentException("El archivo debe ser un binario válido (ELF, PE o Mach-O)");
        }

        Analysis analysis = new Analysis(user, file.getOriginalFilename(), fileBytes);
        analysis.setStatus("PROCESSING");
        analysis.setAnalysisOptions(buildOptionsJson(explain, aiVulns, exploit, mitigate, scan, asmOnly, engine));
        analysis = analysisRepository.save(analysis);

        executeAnalysisAsync(analysis, apiKey, engine, explain, aiVulns, exploit, mitigate, scan, asmOnly);

        return analysis;
    }

    private void executeAnalysisAsync(Analysis analysis, String apiKey, String engine,
                                       boolean explain, boolean aiVulns, boolean exploit, boolean mitigate,
                                       boolean scan, boolean asmOnly) {
        Thread t = new Thread(() -> {
            try {
                performAnalysis(analysis, apiKey, engine, explain, aiVulns, exploit, mitigate, scan, asmOnly);
            } catch (Exception e) {
                logger.error("Error en thread de análisis ID={}", analysis.getId(), e);
                analysis.setStatus("FAILED");
                analysis.setErrorMessage(e.getMessage() != null ? e.getMessage() : "Error desconocido");
                analysis.setCompletedAt(LocalDateTime.now());
                try { analysisRepository.save(analysis); } catch (Exception ex) {}
            }
        });
        t.setName("Analysis-" + analysis.getId());
        t.start();
    }

    private void performAnalysis(Analysis analysis, String apiKey, String engine,
                                  boolean explain, boolean aiVulns, boolean exploit, boolean mitigate,
                                  boolean scan, boolean asmOnly) throws Exception {

        Path binaryFile = null;

        try {
            // 1. El binario sigue yendo a /tmp para no ensuciar tu carpeta
            binaryFile = Files.createTempFile("bin_", "_" + analysis.getBinaryName());
            Files.write(binaryFile, analysis.getBinaryData());

            List<String> command = buildCommand(
                binaryFile.toString(), apiKey, engine,
                explain, aiVulns, exploit, mitigate, scan, asmOnly
            );

            logger.info("Ejecutando: {}", String.join(" ", command));

            ProcessBuilder pb = new ProcessBuilder(command);
            // <--- LA MAGIA ESTÁ AQUÍ: Ejecutamos desde tu carpeta TFG para que encuentre rules.json
            pb.directory(new File(TFG_DIRECTORY)); 
            pb.redirectErrorStream(true);

            Process process = pb.start();

            StringBuilder output = new StringBuilder();
            Thread reader = new Thread(() -> {
                try (BufferedReader br = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
                    String line;
                    while ((line = br.readLine()) != null) {
                        output.append(line).append("\n");
                        logger.debug("[ORQUESTADOR] {}", line);
                    }
                } catch (Exception e) {}
            });
            reader.start();

            int exitCode = process.waitFor();
            reader.join(10_000);

            if (exitCode != 0) {
                throw new RuntimeException("El orquestador falló (exit " + exitCode + ")\n" + output);
            }

            // <--- LA MAGIA ESTÁ AQUÍ: Como lo ejecutamos en la carpeta TFG, los reportes se generan ahí
            String baseName = "reporte_" + binaryFile.getFileName().toString();
            File outDir  = new File(TFG_DIRECTORY); 
            File jsonFile = new File(outDir, baseName + ".json");
            File pdfFile  = new File(outDir, baseName + ".pdf");

            if (jsonFile.exists()) {
                analysis.setJsonReport(new String(Files.readAllBytes(jsonFile.toPath())));
            }
            if (pdfFile.exists()) {
                analysis.setPdfReport(Files.readAllBytes(pdfFile.toPath()));
            }

            analysis.setStatus("COMPLETED");
            analysis.setRiskLevel(extractRiskLevel(analysis.getJsonReport()));
            analysis.setCompletedAt(LocalDateTime.now());

            // 5. Limpiar TODOS los archivos residuales (grafos, JSONs, HTMLs) de tu carpeta TFG
            String[] extensionesResiduales = {".json", ".pdf", ".html", "_scores.json", "_callgraph.png", "_cfg.png"};
            for (String ext : extensionesResiduales) {
                File f = new File(outDir, baseName + ext);
                if (f.exists()) f.delete();
            }

        } catch (Exception e) {
            throw e;
        } finally {
            if (binaryFile != null) {
                try { Files.deleteIfExists(binaryFile); } catch (Exception ignored) {}
            }
            analysisRepository.save(analysis);
        }
    }

    private List<String> buildCommand(String binaryPath, String apiKey, String engine,
                                       boolean explain, boolean aiVulns, boolean exploit, boolean mitigate,
                                       boolean scan, boolean asmOnly) {
        List<String> cmd = new ArrayList<>();
        cmd.add(PYTHON_EXECUTABLE);
        cmd.add(ORQUESTADOR_SCRIPT);
        cmd.add(binaryPath);

        if (asmOnly) cmd.add("--asm-only");

        if (scan) {
            cmd.add("--scan");
            cmd.add("--score");
            cmd.add("--graph");
        }

        if (explain)  cmd.add("--explain");
        if (aiVulns)  cmd.add("--ai-vulns");
        if (exploit)  cmd.add("--exploit");
        if (mitigate) cmd.add("--mitigate");

        boolean needsAi = explain || aiVulns || exploit || mitigate;
        if (needsAi) {
            cmd.add("--ai-engine");
            cmd.add(engine != null && !engine.isEmpty() ? engine : "gemini");

            if (apiKey != null && !apiKey.trim().isEmpty()) {
                cmd.add("--api-key");
                cmd.add(apiKey.trim());
            }
        }
        return cmd;
    }

    private String buildOptionsJson(boolean explain, boolean aiVulns, boolean exploit,
                                     boolean mitigate, boolean scan, boolean asmOnly, String engine) {
        return String.format(
            "{\"explain\":%b,\"ai_vulns\":%b,\"exploit\":%b,\"mitigate\":%b,\"scan\":%b,\"asm_only\":%b,\"engine\":\"%s\"}",
            explain, aiVulns, exploit, mitigate, scan, asmOnly, engine != null ? engine : "gemini"
        );
    }

    private String extractRiskLevel(String jsonReport) {
        if (jsonReport == null) return "UNKNOWN";
        String lower = jsonReport.toLowerCase();
        if (lower.contains("\"nivel\": \"crítico\"")) return "CRITICAL";
        if (lower.contains("\"nivel\": \"alto\""))    return "HIGH";
        if (lower.contains("\"nivel\": \"medio\""))   return "MEDIUM";
        if (lower.contains("\"nivel\": \"bajo\""))    return "LOW";
        return "SAFE";
    }

    private boolean isBinaryFile(byte[] b) {
        if (b == null || b.length < 4) return false;
        if (b[0] == 0x7f && b[1] == 0x45 && b[2] == 0x4c && b[3] == 0x46) return true;
        if (b.length >= 2 && b[0] == 0x4d && b[1] == 0x5a) return true;
        if (b[0] == (byte)0xca && b[1] == (byte)0xfe && b[2] == (byte)0xba
                && (b[3] == (byte)0xbe || b[3] == (byte)0xbf)) return true;
        return false;
    }

    public List<Analysis> getUserAnalyses(User user) { return analysisRepository.findByUserOrderByCreatedAtDesc(user); }
    public Optional<Analysis> getAnalysis(Long id, User user) { return analysisRepository.findByIdAndUser(id, user); }
    public List<Analysis> getUserAnalysesByStatus(User user, String status) { return analysisRepository.findByUserAndStatusOrderByCreatedAtDesc(user, status); }
    public void deleteAnalysis(Long id) { analysisRepository.deleteById(id); }
}
