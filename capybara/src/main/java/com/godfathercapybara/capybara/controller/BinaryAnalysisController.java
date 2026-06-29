package com.godfathercapybara.capybara.controller;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.godfathercapybara.capybara.model.Analysis;
import com.godfathercapybara.capybara.model.User;
import com.godfathercapybara.capybara.service.BinaryAnalysisService;
import com.godfathercapybara.capybara.service.UserService;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.JsonNode;

@RestController
@RequestMapping("/api/analysis")
public class BinaryAnalysisController {

    private static final Logger logger = LoggerFactory.getLogger(BinaryAnalysisController.class);

    @Autowired
    private BinaryAnalysisService binaryAnalysisService;

    @Autowired
    private UserService userService;

    // ─── POST /api/analysis/upload ──────────────────────────────────────────────
    @PostMapping(value = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<Map<String, Object>> uploadBinary(
            @RequestParam("file")                                MultipartFile file,
            @RequestParam(value = "apiKey",    defaultValue = "") String apiKey,
            @RequestParam(value = "engine",    defaultValue = "gemini") String engine,
            @RequestParam(value = "explain",   defaultValue = "false") boolean explain,
            @RequestParam(value = "ai_vulns",  defaultValue = "false") boolean aiVulns,
            @RequestParam(value = "exploit",   defaultValue = "false") boolean exploit,
            @RequestParam(value = "mitigate",  defaultValue = "false") boolean mitigate,
            @RequestParam(value = "scan",      defaultValue = "false") boolean scan,
            @RequestParam(value = "asm_only",  defaultValue = "false") boolean asmOnly,
            Authentication authentication) {

        try {
            if (authentication == null) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                        .body(Map.of("error", "Usuario no autenticado"));
            }

            Optional<User> user = userService.findByUsername(authentication.getName());
            if (user.isEmpty()) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                        .body(Map.of("error", "Usuario no encontrado"));
            }

            // Al menos una opción de análisis debe estar seleccionada
            if (!explain && !aiVulns && !exploit && !mitigate && !scan) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Debes seleccionar al menos una opción de análisis"));
            }

            Analysis analysis = binaryAnalysisService.analyzeBinary(
                    user.get(), file, apiKey, engine,
                    explain, aiVulns, exploit, mitigate, scan, asmOnly
            );

            Map<String, Object> response = new HashMap<>();
            response.put("success",    true);
            response.put("message",    "Análisis iniciado");
            response.put("analysisId", analysis.getId());
            response.put("status",     analysis.getStatus());
            response.put("binaryName", analysis.getBinaryName());

            return ResponseEntity.accepted().body(response);

        } catch (IllegalArgumentException e) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", e.getMessage()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al procesar el archivo: " + e.getMessage()));
        }
    }

    // ─── GET /api/analysis/status/{id} ─────────────────────────────────────────
    @GetMapping("/status/{id}")
    public ResponseEntity<Map<String, Object>> getAnalysisStatus(
            @PathVariable Long id, Authentication authentication) {

        try {
            if (authentication == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

            Optional<User> user = userService.findByUsername(authentication.getName());
            if (user.isEmpty()) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();

            Optional<Analysis> analysis = binaryAnalysisService.getAnalysis(id, user.get());
            if (analysis.isEmpty()) return ResponseEntity.notFound().build();

            Analysis a = analysis.get();
            Map<String, Object> response = new HashMap<>();
            response.put("id",              a.getId());
            response.put("status",          a.getStatus());
            response.put("binaryName",      a.getBinaryName());
            response.put("fileSize",        a.getFileSize());
            response.put("riskLevel",       a.getRiskLevel());
            response.put("createdAt",       a.getCreatedAt());
            response.put("completedAt",     a.getCompletedAt());
            response.put("analysisOptions", a.getAnalysisOptions());

            if ("FAILED".equals(a.getStatus())) {
                response.put("error", a.getErrorMessage());
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ─── GET /api/analysis/download/{id} ───────────────────────────────────────
    @GetMapping("/download/{id}")
    public ResponseEntity<byte[]> downloadReport(
            @PathVariable Long id, Authentication authentication) {

        try {
            if (authentication == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

            Optional<User> user = userService.findByUsername(authentication.getName());
            if (user.isEmpty()) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();

            Optional<Analysis> analysis = binaryAnalysisService.getAnalysis(id, user.get());
            if (analysis.isEmpty()) return ResponseEntity.notFound().build();

            Analysis a = analysis.get();
            if (a.getPdfReport() == null || "PROCESSING".equals(a.getStatus())) {
                return ResponseEntity.noContent().build();
            }

            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION,
                            "attachment; filename=\"" + a.getBinaryName() + "_report.pdf\"")
                    .contentType(MediaType.APPLICATION_PDF)
                    .body(a.getPdfReport());

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ─── GET /api/analysis/json/{id} ───────────────────────────────────────────
    @GetMapping("/json/{id}")
    public ResponseEntity<Map<String, Object>> getJsonReport(
            @PathVariable Long id, Authentication authentication) {

        try {
            if (authentication == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

            Optional<User> user = userService.findByUsername(authentication.getName());
            if (user.isEmpty()) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();

            Optional<Analysis> analysis = binaryAnalysisService.getAnalysis(id, user.get());
            if (analysis.isEmpty()) return ResponseEntity.notFound().build();

            Analysis a = analysis.get();
            Map<String, Object> response = new HashMap<>();
            response.put("status",     a.getStatus());
            response.put("binaryName", a.getBinaryName());
            response.put("riskLevel",  a.getRiskLevel());
            if (a.getJsonReport() != null) {
                response.put("report", a.getJsonReport());
            }

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ─── GET /api/analysis/list ─────────────────────────────────────────────────
    @GetMapping("/list")
    public ResponseEntity<?> listAnalyses(
            @RequestParam(value = "status", required = false) String status,
            Authentication authentication) {

        try {
            logger.info("=== listAnalyses | user: {} ===",
                authentication != null ? authentication.getName() : "null");

            if (authentication == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

            Optional<User> user = userService.findByUsername(authentication.getName());
            if (user.isEmpty()) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();

            List<Analysis> analyses = (status != null && !status.isEmpty())
                    ? binaryAnalysisService.getUserAnalysesByStatus(user.get(), status)
                    : binaryAnalysisService.getUserAnalyses(user.get());

            ObjectMapper mapper = new ObjectMapper();
            List<Map<String, Object>> list = new ArrayList<>();
            
            for (Analysis a : analyses) {
                Map<String, Object> item = new HashMap<>();
                item.put("id",           a.getId());
                item.put("binaryName",   a.getBinaryName() != null ? a.getBinaryName() : "unknown");
                item.put("status",       a.getStatus()     != null ? a.getStatus()     : "UNKNOWN");
                item.put("riskLevel",    a.getRiskLevel()  != null ? a.getRiskLevel()  : "UNKNOWN");
                item.put("fileSize",     a.getFileSize()   != null ? a.getFileSize()   : 0L);
                item.put("createdAt",    a.getCreatedAt());
                item.put("completedAt",  a.getCompletedAt());
                item.put("hasPdf",       "COMPLETED".equals(a.getStatus()));
                item.put("hasJson",      "COMPLETED".equals(a.getStatus()));
                item.put("errorMessage", a.getErrorMessage());

                // Extraer el top 3 de vulnerabilidades del JSON
                List<Map<String, String>> topFindings = new ArrayList<>();
                if ("COMPLETED".equals(a.getStatus()) && a.getJsonReport() != null) {
                    try {
                        JsonNode root = mapper.readTree(a.getJsonReport());
                        JsonNode scores = root.get("risk_scores");
                        if (scores != null && scores.isArray()) {
                            for (int i = 0; i < Math.min(3, scores.size()); i++) {
                                JsonNode sc = scores.get(i);
                                if (sc.get("score").asDouble() > 0) {
                                    topFindings.add(Map.of(
                                        "func", sc.get("funcion").asText(),
                                        "level", sc.get("nivel").asText()
                                    ));
                                }
                            }
                        }
                    } catch (Exception e) {
                        logger.warn("Error parseando JSON para findings: {}", e.getMessage());
                    }
                }
                item.put("topFindings", topFindings);
                // Incluir opciones de análisis y motor de IA usado (si está disponible)
                item.put("analysisOptions", a.getAnalysisOptions());
                try {
                    String aiEngine = "N/A";
                    if (a.getAnalysisOptions() != null) {
                        JsonNode opts = mapper.readTree(a.getAnalysisOptions());
                        if (opts.has("engine")) aiEngine = opts.get("engine").asText();
                    }
                    item.put("aiEngine", aiEngine);
                } catch (Exception e) {
                    logger.warn("Error parseando analysisOptions para ID {}: {}", a.getId(), e.getMessage());
                    item.put("aiEngine", "N/A");
                }
                list.add(item);
            }

            Map<String, Object> response = new HashMap<>();
            response.put("success",  true);
            response.put("total",    list.size());
            response.put("analyses", list);

            logger.info("Retornando {} análisis", list.size());
            return ResponseEntity.ok(response);

        } catch (Exception e) {
            logger.error("ERROR en listAnalyses", e);

            StringWriter sw = new StringWriter();
            e.printStackTrace(new java.io.PrintWriter(sw));
            logger.error("Stack trace:\n{}", sw.toString());

            Map<String, Object> err = new HashMap<>();
            err.put("success", false);
            err.put("error",   e.getMessage() != null ? e.getMessage() : "Unknown error");
            err.put("type",    e.getClass().getSimpleName());
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(err);
        }
    }

    // ─── DELETE /api/analysis/{id} ──────────────────────────────────────────────
    @DeleteMapping("/{id}")
    public ResponseEntity<Map<String, Object>> deleteAnalysis(
            @PathVariable Long id, Authentication authentication) {

        try {
            if (authentication == null) return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();

            Optional<User> user = userService.findByUsername(authentication.getName());
            if (user.isEmpty()) return ResponseEntity.status(HttpStatus.FORBIDDEN).build();

            Optional<Analysis> analysis = binaryAnalysisService.getAnalysis(id, user.get());
            if (analysis.isEmpty()) return ResponseEntity.notFound().build();

            binaryAnalysisService.deleteAnalysis(id);

            return ResponseEntity.ok(Map.of(
                "success", true,
                "message", "Análisis eliminado correctamente"
            ));

        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(Map.of("error", "Error al eliminar: " + e.getMessage()));
        }
    }
}
