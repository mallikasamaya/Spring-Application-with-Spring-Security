package com.example.demo.Student;

public class Student {

    private final Integer studentId;

    public Integer getStudentId() {
        return studentId;
    }

    public String getName() {
        return name;
    }

    private final String name;

    public Student(Integer studentId, String name) {
        this.studentId = studentId;
        this.name = name;
    }

    @Override
    public String toString() {
        return "Student{" +
            "studentId=" + studentId +
            ", name='" + name + '\'' +
            '}';
    }
}
