using System.ComponentModel.DataAnnotations.Schema;

namespace IdentityApp.Models {

    public class Product {
        public long Id { get; set; }

        public string Name { get; set; }

        [Column(TypeName = "decimal(8, 2)")]
        public decimal Price { get; set; }

        public string Category { get; set; }
    }
}
