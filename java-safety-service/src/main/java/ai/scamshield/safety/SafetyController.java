package ai.scamshield.safety;

import java.util.Map;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/safety")
@CrossOrigin
public class SafetyController {
    private final SafetyService service;
    public SafetyController(SafetyService service) { this.service = service; }

    @PostMapping("/payment") public Map<String, Object> payment(@RequestBody Map<String, String> request) { return service.payment(request); }
    @PostMapping("/sender") public Map<String, Object> sender(@RequestBody Map<String, String> request) { return service.sender(request); }
    @PostMapping("/protection") public Map<String, Object> protection(@RequestBody Map<String, String> request) { return service.protection(request); }
    @GetMapping("/health") public Map<String, String> health() { return Map.of("status", "ok"); }
}
