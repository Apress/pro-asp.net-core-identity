namespace IdentityTodo.Data {

    public class TodoItem {

        public long Id { get; set; }

        public string? Task { get; set; }

        public bool Complete { get; set; }

        public string? Owner { get; set; }
    }
}
