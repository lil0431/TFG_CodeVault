package com.godfathercapybara.capybara.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import com.godfathercapybara.capybara.model.Analysis;
import com.godfathercapybara.capybara.model.User;

@Repository
public interface AnalysisRepository extends JpaRepository<Analysis, Long> {
    List<Analysis> findByUserOrderByCreatedAtDesc(User user);
    List<Analysis> findByUserAndStatusOrderByCreatedAtDesc(User user, String status);
    Optional<Analysis> findByIdAndUser(Long id, User user);
    Long countByUserAndStatus(User user, String status);
}
