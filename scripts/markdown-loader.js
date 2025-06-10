// Simple markdown to HTML converter
function convertMarkdownToHTML(markdown) {
    return markdown
        .replace(/^### (.*$)/gm, '<h4>$1</h4>')
        .replace(/^## (.*$)/gm, '<h3>$1</h3>')
        .replace(/^# (.*$)/gm, '<h2>$1</h2>')
        .replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.*?)\*/g, '<em>$1</em>')
        .replace(/`(.*?)`/g, '<code>$1</code>')
        .replace(/```[\s\S]*?```/g, function(match) {
            const code = match.slice(3, -3);
            return '<pre><code>' + code + '</code></pre>';
        })
        .replace(/\n\n/g, '</p><p>')
        .replace(/\n/g, '<br>')
        .replace(/^(.*)$/gm, '<p>$1</p>')
        .replace(/<p><\/p>/g, '')
        .replace(/^<p>(<h[1-4]>.*<\/h[1-4]>)<\/p>$/gm, '$1')
        .replace(/^<p>(<pre><code>[\s\S]*?<\/code><\/pre>)<\/p>$/gm, '$1');
}

// Load markdown files from a directory
async function loadMarkdownFiles(directory) {
    const contentDiv = document.getElementById('markdown-content');
    
    // Known markdown files for each directory
    const directoryFiles = {
        'vulnerabilities': ['sql-injection.md'],
        'security': ['authentication.md'],
        'attacks': ['prompt-injection.md'],
        'resources': ['security-tools.md'],
        'contribute': ['README.md']
    };
    
    // Also check for common filenames
    const commonFiles = [
        'README.md',
        'index.md',
        'overview.md',
        'introduction.md',
        'guide.md'
    ];
    
    // Combine directory-specific files with common files
    const filesToCheck = [
        ...(directoryFiles[directory] || []),
        ...commonFiles
    ];
    
    // Remove duplicates
    const uniqueFiles = [...new Set(filesToCheck)];
    
    let hasContent = false;
    
    for (const file of uniqueFiles) {
        try {
            const response = await fetch(`${directory}/${file}`);
            if (response.ok) {
                const markdown = await response.text();
                const html = convertMarkdownToHTML(markdown);
                
                const fileDiv = document.createElement('div');
                fileDiv.className = 'markdown-file';
                fileDiv.innerHTML = `
                    <h5>📄 ${file}</h5>
                    ${html}
                `;
                
                contentDiv.appendChild(fileDiv);
                hasContent = true;
            }
        } catch (error) {
            // File doesn't exist or can't be loaded, continue to next
            continue;
        }
    }
    
    if (!hasContent) {
        contentDiv.innerHTML = `
            <div class="alert info">
                <strong>📝 Content Coming Soon:</strong> Markdown files will be loaded from the <code>${directory}/</code> directory.
                <br>Add your <code>.md</code> files to contribute content to this section.
            </div>
        `;
    }
}

// Initialize markdown loading when DOM is ready
document.addEventListener('DOMContentLoaded', function() {
    // This will be called by individual pages
});