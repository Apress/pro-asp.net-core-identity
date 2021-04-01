using IdentityTodo.Data;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityTodo.Pages {

    [Authorize]
    public class IndexModel : PageModel {
        private ApplicationDbContext Context;

        public IndexModel(ApplicationDbContext ctx) {
            Context = ctx;
        }

        [BindProperty(SupportsGet = true)]
        public bool ShowComplete { get; set; }

        public IEnumerable<TodoItem> TodoItems { get; set; }

        public void OnGet() {
            TodoItems = Context.TodoItems
                .Where(t => t.Owner == User.Identity.Name).OrderBy(t => t.Task);
            if (!ShowComplete) {
                TodoItems = TodoItems.Where(t => !t.Complete);
            }
            TodoItems = TodoItems.ToList();
        }

        public IActionResult OnPostShowComplete() {
            return RedirectToPage(new { ShowComplete });
        }

        public async Task<IActionResult> OnPostAddItemAsync(string task) {
            if (!string.IsNullOrEmpty(task)) {
                TodoItem item = new TodoItem {
                    Task = task,
                    Owner = User.Identity.Name,
                    Complete = false
                };
                await Context.AddAsync(item);
                await Context.SaveChangesAsync();
            }
            return RedirectToPage(new { ShowComplete });
        }

        public async Task<IActionResult> OnPostMarkItemAsync(long id) {
            TodoItem item = Context.TodoItems.Find(id);
            if (item != null) {
                item.Complete = !item.Complete;
                await Context.SaveChangesAsync();
            }
            return RedirectToPage(new { ShowComplete });
        }
    }
}
