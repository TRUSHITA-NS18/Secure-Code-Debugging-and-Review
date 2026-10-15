from rag_engine import analyze_code
sample = '''
char *password = "demo12345";
void test(char *user) {
  char buffer[8];
  strcpy(buffer, user);
  system(user);
  int arr[2];
  int x = arr[5];
  int TODO = 0;
  FILE *fp = fopen("demo.txt", "r");
}
'''
expected = {"SEC-001","SEC-002","MEM-001","MEM-002","RES-001","STYLE-001"}
found = {f["rule_id"] for f in analyze_code(sample,"evaluation.c")}
print("Expected:", sorted(expected))
print("Detected:", sorted(found))
if expected - found:
    print("Missing:", sorted(expected-found))
    raise SystemExit(1)
print("PASS: expected smoke-test rules detected.")
