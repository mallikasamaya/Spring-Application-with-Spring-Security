package com.example.demo.Student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("api/students")
public class StudentController {

    private static final List<Student> students = Arrays.asList(
        new Student(1,"aaaa"),
        new Student(2,"bbbb"),
        new Student(3,"cccc")
    );

    @GetMapping(path = "{studentId}")
    public Student getStudent(@PathVariable Integer studentId) {
        return students.stream()
            .filter(student -> studentId.equals(student.getStudentId()))
            .findFirst()
            .orElseThrow(() -> new IllegalStateException("Student " + studentId + " doesnot exist"));
    }
}

