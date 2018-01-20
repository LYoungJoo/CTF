# Spectre & Meltdown 취약점 분석
### 1. Spectre
- Variant 1: bounds check bypass (CVE-2017-5753)
- Variant 2: branch target injection (CVE-2017-5715)

이 취약점은 CPU의 Branch Prediction에 의해서 발생한 취약점이다.
### Pipeline
CPU는 Instruction이 요구하는 동작을 수행하기 위해서 아래와 같은 과정을 거친다.
- Instruction Fetch
- Instruction Decode
- Instruction Execution
- Register Write Back

그런데 하나의 Instruction이 처리될 때까지 다음 Instruction이 처리되지 않고 기다리고 있다면, Instruction의 특정 단계를 처리하는 동안 다른 단계를 처리하는 부분은 아무것도 하지 않는다. 그렇기 때문에 효율적으로 Instruction을 실행시키기 위해서 고안된 방법이다.
### Pipeline Hazard
위에서 다룬 Pipeline 방식에도 위험이 존재하는데 크게 아래와 같다.
- Structural Hazard
- Data Hazard
- Control Hazard

이 보고서에서 중요하게 볼 부분은 Control Hazrad 이다.
Control Hazard는 분기명령 중 분기가 결정되는 시점에 이미 파이프라인에 후속 명령들이 존재하여 발생하는 위험이다. 이 위험은 분기가 True일 경우에 실행하지 말았어야 할 명령들을 실행하여 문제가 된다.
### Dynamic Branch Prediction
Pipeline에서 Branch와 jmp와 같은 memory 주소를 뛰어넘는 명령을 수행할 때 자주 발생하는 Control Hazard는 다음 명령이 바뀌기 때문에 분기전에 다음 명령어들을 미리 실행시켜두는 것이 필요하지 않다. Control Hazard에 대한 가장 쉬운 해결책은 분기을 만나면 그 stage에서 멈추고 분기 명령을 수행할 때까지 기다리는 것이다. 하지만 이렇게 되면 Pipeline에 원래 목적과 맞지 않기 때문에 제안된 방법이 Branch Prediction이다.
Branch Prediction은 branch가 성립하지 않을 거라는 가정하에 다음 명령을 실행시키는 Predict-Not-Taken 방식과 반대로 branch가 무조건 성립할 거라는 가정하에 branch가 성립한 이후에 명령들을 미리 실행시키는 Predict-Taken방식이 존재한다. 또한 Static Branch Prediction은 Predict-Not-Taken과 Predict-Taken 방식을 그대로 진행하되, 만약 잘못된 명령을 실행시켰다면 해당 명령을 flush시키고 다시 돌아가는 형태로 구현되어 있다. 즉 명령의 타입에 의해 Prediction 구조가 결정되는 것이다. 하지만 이것은 Prediction이 잘못 판단되면 많은 명령이 flush 되고 다시 돌아가는 비효율적인 결과가 발생한다. 그렇기 때문에 유동적으로 Prediction 구조를 결정하는 것이 Dynamic Branch Prediction이다.
Dynamic Branch Prediction의 경우에는 Branch Prediction Buffer가 잘못 명령어를 실행하는 횟수를 체크하여 더 높은 확률의 방식을 선정한다. 즉 Runtime 내에 Predict-Not-Taken과 Predict-Taken이 변경된다.
### Spectre
Spectre는 Branch Prediction으로 인하여 실행되는 명령 때문에 취약점이 발생한다. Predict-Taken 상태에서는 분기문의 다음 명령까지 실행시키는데 이때 실제로 코드상에서는 실행되지 않는 부분이 실행될 수 있고, 이로 인하여 캐시에 값이 저장되면 cache timing attack을 이용해 memory leak을 하는 취약점이다. 아래 POC에서 더 상세히 설명하겠다.
