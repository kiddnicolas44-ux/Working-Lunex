return {
    ["Minify"] = {
        LuaVersion = "Lua51";
        VarNamePrefix = "";
        NameGenerator = "MangledShuffled";
        PrettyPrint = false;
        Seed = 0;
        Steps = {}
    };
    ["Weak"] = {
        LuaVersion = "Lua51";
        VarNamePrefix = "";
        NameGenerator = "MangledShuffled";
        PrettyPrint = false;
        Seed = 0;
        Steps = {
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                }
            },
            {
                Name = "WrapInFunction";
                Settings = {}
            },
        }
    };
    ["Medium"] = {
        LuaVersion = "Lua51";
        VarNamePrefix = "";
        NameGenerator = "MangledShuffled";
        PrettyPrint = false;
        Seed = 0;
        Steps = {
            {
                Name = "EncryptStrings";
                Settings = {};
            },
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                    Shuffle     = true;
                    Rotate      = true;
                    LocalWrapperTreshold = 0;
                }
            },
            {
                Name = "NumbersToExpressions";
                Settings = {}
            },
            {
                Name = "WrapInFunction";
                Settings = {}
            },
        }
    };
    ["Strong"] = {
        LuaVersion = "Lua51";
        VarNamePrefix = "";
        NameGenerator = "MangledShuffled";
        PrettyPrint = false;
        Seed = 0;
        Steps = {
            {
                Name = "EncryptStrings";
                Settings = {};
            },
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = true;
                    Shuffle     = true;
                    Rotate      = true;
                    LocalWrapperTreshold = 0;
                }
            },
            {
                Name = "NumbersToExpressions";
                Settings = {}
            },
            {
                Name = "WrapInFunction";
                Settings = {}
            },
        }
    },
    ["Maximum"] = {
        LuaVersion = "Lua51";
        VarNamePrefix = "";
        NameGenerator = "MangledShuffled";
        PrettyPrint = false;
        Seed = 0;
        Steps = {
            {
                Name = "Vmify";
                Settings = {};
            },
            {
                Name = "EncryptStrings";
                Settings = {};
            },
            {
                Name = "AddVararg";
                Settings = {};
            },
            {
                Name = "SplitStrings";
                Settings = {
                    MinLength = 3;
                    MaxLength = 8;
                    ConcatenationType = "table";
                };
            },
            {
                Name = "ProxifyLocals";
                Settings = {};
            },
            {
                Name = "ConstantArray";
                Settings = {
                    Treshold    = 1;
                    StringsOnly = false;
                    Shuffle     = true;
                    Rotate      = true;
                    LocalWrapperTreshold = 1;
                    LocalWrapperCount = 2;
                    LocalWrapperArgCount = 5;
                    MaxWrapperOffset = 65535;
                }
            },
            {
                Name = "NumbersToExpressions";
                Settings = {}
            },
            {
                Name = "EncryptStrings";
                Settings = {};
            },
            {
                Name = "WrapInFunction";
                Settings = {}
            },
        }
    },
}
