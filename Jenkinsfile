pipeline {
  agent any
  parameters {
    string(name: 'WORKSPACE', defaultValue: 'development', description:'setting up workspace for terraform')
  }
  environment {
    TF_HOME = tool('terraform-0.15.3')
    TF_IN_AUTOMATION = "true"
    PATH = "$TF_HOME:$PATH"
    ACCESS_KEY = credentials('AWS_ACCESS_KEY_ID')
    SECRET_KEY = credentials('AWS_SECRET_ACCESS_KEY')
  }
  stages {
    stage('TerraformInit'){
        steps {
            sh "terraform init -input=false"
        }
    }
    stage('Terraform workspace') {
        steps {
          script {
                try {
                    sh "terraform workspace new ${params.WORKSPACE}"
                } catch (err) {
                    sh "terraform workspace select ${params.WORKSPACE}"
                }
          }
        }
    }
    stage('TerraformPlan'){
        steps {
            script {
                sh "terraform plan -var 'access_key=$ACCESS_KEY' -var 'secret_key=$SECRET_KEY' -out terraform.tfplan;echo \$? > status"
                stash name: "terraform-plan", includes: "terraform.tfplan"
            }
        }
    }
    stage("TerraformSelect") {
       steps {
           script {
                env.NEXT_STEP = input message: 'User input required', ok: 'Select',
                parameters: [choice(name: 'NEXT_STEP', choices: 'apply\ndestroy\nnothing', description: 'What would you like to do next?')]
           }
           echo "${env.NEXT_STEP}"
       }
    }
    stage('TerraformApply'){
        when {
          expression {
            return env.NEXT_STEP == 'apply';
          }
        }
        steps {
            script{                    
                unstash "terraform-plan"
                sh "terraform apply terraform.tfplan"
            }
        }
    }
    stage('TerraformDestroy'){
        when {
          expression {
            return env.NEXT_STEP == 'destroy';
          }
        }
        steps {
            script{
                sh "terraform destroy -auto-approve -var 'access_key=$ACCESS_KEY' -var 'secret_key=$SECRET_KEY' "
            }
        }
    }
    stage('TerraformNothing'){
        when {
          expression {
            return env.NEXT_STEP == 'nothing';
          }
        }
        steps {
            script{
                echo "terraform did nothing to the infrastructure"
            }
        }
    }
  }
  
}
