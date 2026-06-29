package com.godfathercapybara.capybara.model;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;

@Entity(name = "ANALYSIS")
@Table(name = "analysis")
public class Analysis {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne
    @JoinColumn(name = "user_id", nullable = false)
    private User user;

    @Column(name = "binary_name", nullable = false)
    private String binaryName;

    @Column(name = "binary_data", nullable = false, columnDefinition = "LONGBLOB")
    private byte[] binaryData;

    @Column(name = "pdf_report", columnDefinition = "LONGBLOB")
    private byte[] pdfReport;

    @Column(name = "json_report", columnDefinition = "LONGTEXT")
    private String jsonReport;

    @Column(name = "status")
    private String status; // PROCESSING, COMPLETED, FAILED

    @Column(name = "risk_level")
    private String riskLevel; // LOW, MEDIUM, HIGH, CRITICAL

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    @Column(name = "completed_at")
    private LocalDateTime completedAt;

    @Column(name = "error_message")
    private String errorMessage;

    @Column(name = "analysis_options", columnDefinition = "TEXT")
    private String analysisOptions; // JSON con explain, ai_vulns, exploit, mitigate

    @Column(name = "file_size")
    private Long fileSize;

    // Constructores
    public Analysis() {
        this.status = "PROCESSING";
        this.createdAt = LocalDateTime.now();
    }

    public Analysis(User user, String binaryName, byte[] binaryData) {
        this.user = user;
        this.binaryName = binaryName;
        this.binaryData = binaryData;
        this.status = "PROCESSING";
        this.createdAt = LocalDateTime.now();
        this.fileSize = (long) binaryData.length;
    }

    // Getters y Setters
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getBinaryName() {
        return binaryName;
    }

    public void setBinaryName(String binaryName) {
        this.binaryName = binaryName;
    }

    public byte[] getBinaryData() {
        return binaryData;
    }

    public void setBinaryData(byte[] binaryData) {
        this.binaryData = binaryData;
    }

    public byte[] getPdfReport() {
        return pdfReport;
    }

    public void setPdfReport(byte[] pdfReport) {
        this.pdfReport = pdfReport;
    }

    public String getJsonReport() {
        return jsonReport;
    }

    public void setJsonReport(String jsonReport) {
        this.jsonReport = jsonReport;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getRiskLevel() {
        return riskLevel;
    }

    public void setRiskLevel(String riskLevel) {
        this.riskLevel = riskLevel;
    }

    public LocalDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(LocalDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public LocalDateTime getCompletedAt() {
        return completedAt;
    }

    public void setCompletedAt(LocalDateTime completedAt) {
        this.completedAt = completedAt;
    }

    public String getErrorMessage() {
        return errorMessage;
    }

    public void setErrorMessage(String errorMessage) {
        this.errorMessage = errorMessage;
    }

    public String getAnalysisOptions() {
        return analysisOptions;
    }

    public void setAnalysisOptions(String analysisOptions) {
        this.analysisOptions = analysisOptions;
    }

    public Long getFileSize() {
        return fileSize;
    }

    public void setFileSize(Long fileSize) {
        this.fileSize = fileSize;
    }
}
