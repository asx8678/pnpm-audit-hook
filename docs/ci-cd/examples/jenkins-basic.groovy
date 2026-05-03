// Basic Jenkins Security Audit Pipeline
// This pipeline runs security audits in Jenkins

pipeline {
    agent any
    
    environment {
        NODE_ENV = 'production'
        AUDIT_SEVERITY = 'high'
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
            }
        }
        
        stage('Setup') {
            steps {
                sh 'npm install -g pnpm'
                sh 'pnpm install --frozen-lockfile'
            }
        }
        
        stage('Security Audit') {
            steps {
                sh 'pnpm audit'
            }
            post {
                always {
                    echo 'Security audit completed'
                }
                failure {
                    echo 'Security audit failed'
                }
            }
        }
        
        stage('Build') {
            steps {
                sh 'pnpm run build'
            }
        }
        
        stage('Deploy') {
            when {
                branch 'main'
            }
            steps {
                sh './deploy.sh'
            }
        }
    }
    
    post {
        always {
            cleanWs()
        }
    }
}