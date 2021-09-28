package com.example.security.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {

    private static final List<Student> STUDENTS = List.of(
            new Student(1, "Denis"),
            new Student(2, "Fedor"),
            new Student(3, "Petr")
    );

    @GetMapping(path = "{id}")
    public Student getStudent(@PathVariable Integer id) {
        return STUDENTS.stream().filter(student -> student.getId().equals(id))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Student " + id + " does not exist"));
    }
}
