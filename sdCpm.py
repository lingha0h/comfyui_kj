class cpm_textInput:
    CATEGORY = "sdCpm"
    @classmethod
    def INPUT_TYPES(cls):
        return {
            "required": {
                "text": ("STRING", {"default": "", "multiline": True, "placeholder": "输入文本"}),
            }
        }
    RETURN_TYPES = ("STRING",)
    FUNCTION = "getText"
   

    @staticmethod
    def getText(text):
        return (text,)