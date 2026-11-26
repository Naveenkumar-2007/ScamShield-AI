# Companion Safety Engine

This internal service powers Payment Safety, Sender Trust, and Account Protection checks. It is not branded separately in the ScamShield interface.

Run it with Java 21 and Maven:

```powershell
cd java-safety-service
mvn spring-boot:run
```

Then start ScamShield with `SAFETY_ENGINE_URL=http://127.0.0.1:8081`. If it is not running, ScamShield safely uses its local equivalent checks so the website remains available.
